/* tr_record.c -- see tr_record.h.
 *
 * Three properties matter more than speed here:
 *
 *   1. A line is either complete or absent. It is built in a private
 *      per-frame buffer and handed to fwrite as one blob under one lock, so
 *      concurrent threads cannot interleave. A final count/byte-count/SHA-256
 *      footer binds every preceding raw byte, and a same-directory atomic
 *      promotion makes only a fully flushed/committed/closed file authoritative.
 *   2. A tap that faults invalidates the whole run, so every read of caller
 *      memory is probed with VirtualQuery and then performed inside an SEH
 *      guard. A bad pointer invalidates evidence instead of faulting the host.
 *   3. No CRT locale dependence. Integers and hex are formatted by hand;
 *      the one snprintf (doubles) is post-processed because the CRT emits
 *      the host locale's decimal separator and JSON only accepts '.'.
 */

#define _CRT_SECURE_NO_WARNINGS 1
#define WIN32_LEAN_AND_MEAN 1
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <io.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "tr_record.h"

/* trace.py TRACE_VERSION. */
#define TR_WIRE_VERSION 1

#define TR_BUF_MIN 512
#define TR_NOTE_BUDGET 64
#define TR_ENV_MAX_CHARS 32768
#define TR_ENV_RETRIES 4

/* clang emits the SEH scope table only for faults raised in a CALLEE of the
   guarded block: an access violation on an instruction inside the __try
   function itself walks straight past the handler (verified, clang 22,
   x86_64-pc-windows-msvc). Every fallible access therefore goes through a
   noinline worker called from the __try. Do not "simplify" that away. */
#if defined(_MSC_VER) || defined(__SEH__)
#define TR_SEH 1
#else
#define TR_SEH 0
#endif

#define TR_READABLE (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | \
                     PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |      \
                     PAGE_EXECUTE_WRITECOPY)

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
    int    oom;
} tr_buf;

typedef struct tr_thread tr_thread;

struct tr_call {
    tr_buf      b;
    tr_thread  *ts;
    const char *sym;
    LONG        seq;
    LONG        parent;
    int         has_parent;
    int         depth;
    int         section;        /* 0 = header only, 1 = "in" open, 2 = "out" open */
    int         items;          /* members written in the open section */
    int         heap;           /* frame came from the heap, not the slot array */
    int         ret_kind;       /* 0 none, 1 integer, 2 double, 3 void */
    long long   ret_i;
    double      ret_f;
    char        ret_k[16];
    int         has_err;
    unsigned long err;
};

struct tr_thread {
    tr_thread *next;
    tr_buf     scratch;         /* decoded strings land here before escaping */
    int        depth;
    int        overflow_noted;
    LONG       stack[TR_MAX_DEPTH];
    tr_call    slots[TR_MAX_DEPTH];
};

static CRITICAL_SECTION g_lock;
static INIT_ONCE     g_once = INIT_ONCE_STATIC_INIT;
static DWORD         g_tls = TLS_OUT_OF_INDEXES;
static FILE         *g_fp;
static wchar_t      *g_final_path;
static wchar_t      *g_partial_path;
static tr_thread    *g_threads;
static size_t        g_maxcap = TR_MAX_CAPTURE;
static int           g_started;      /* tr_init has run */
static volatile LONG g_ready;        /* recording is live */
static volatile LONG g_faulted;      /* sticky: evidence can never complete */
static volatile LONG g_seq;
static volatile LONG g_note_budget = TR_NOTE_BUDGET;
static volatile LONG g_inflight;
static volatile LONG g_temp_nonce;

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char block[64];
    size_t used;
} tr_sha256;

static tr_sha256     g_sha;
static uint64_t      g_payload_records;
static wchar_t       g_env_path[TR_ENV_MAX_CHARS];
static wchar_t       g_env_pass[16];

static const char HEXD[] = "0123456789abcdef";

/* A recorder failure must be irreversible for this process.  In particular,
   never let a later successful write erase the fact that an earlier call or
   field was lost.  InterlockedExchange is safe both inside and outside the
   sink lock and also stops new frames from being admitted. */
static void recorder_fault(void)
{
    InterlockedExchange(&g_faulted, 1);
    InterlockedExchange(&g_ready, 0);
}

static int recorder_is_faulted(void)
{
    return InterlockedCompareExchange(&g_faulted, 0, 0) != 0;
}

#ifdef TR_TEST_FAULT_INJECT
/* Test-only failure injection.  Production builds contain neither the
   control variable nor these branches.  Syntax: SHIMFORGE_TR_FAIL=site:N,
   where N is the one-based invocation of site to fail. */
static volatile LONG g_test_alloc_calls;
static volatile LONG g_test_write_calls;
static volatile LONG g_test_flush_calls;
static volatile LONG g_test_close_calls;
static volatile LONG g_test_commit_calls;
static volatile LONG g_test_tls_calls;
static volatile LONG g_test_move_calls;

static int test_fail(const wchar_t *site, volatile LONG *counter)
{
    wchar_t spec[64];
    DWORD n;
    size_t i = 0;
    unsigned long want = 0;
    LONG call;

    n = GetEnvironmentVariableW(L"SHIMFORGE_TR_FAIL", spec,
                                (DWORD)(sizeof spec / sizeof spec[0]));
    if (!n || n >= (DWORD)(sizeof spec / sizeof spec[0]))
        return 0;
    while (site[i] && spec[i] == site[i])
        i++;
    if (site[i] || spec[i++] != L':')
        return 0;
    if (spec[i] < L'1' || spec[i] > L'9')
        return 0;
    while (spec[i]) {
        if (spec[i] < L'0' || spec[i] > L'9' ||
            want > (0x7ffffffful - 9ul) / 10ul)
            return 0;
        want = want * 10ul + (unsigned long)(spec[i] - L'0');
        i++;
    }
    call = InterlockedIncrement(counter);
    return (unsigned long)call == want;
}
#else
#define test_fail(site, counter) 0
#endif

static void *tr_heap_alloc(DWORD flags, size_t n)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"alloc", &g_test_alloc_calls))
        return NULL;
#endif
    return HeapAlloc(GetProcessHeap(), flags, n);
}

static void *tr_heap_realloc(DWORD flags, void *p, size_t n)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"alloc", &g_test_alloc_calls))
        return NULL;
#endif
    return HeapReAlloc(GetProcessHeap(), flags, p, n);
}

static void tr_heap_free(void *p)
{
    if (p)
        (void)HeapFree(GetProcessHeap(), 0, p);
}

static size_t tr_fwrite(const void *p, size_t size, size_t n, FILE *fp)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"write", &g_test_write_calls))
        return 0;
#endif
    return fwrite(p, size, n, fp);
}

static int tr_fflush(FILE *fp)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"flush", &g_test_flush_calls))
        return EOF;
#endif
    return fflush(fp);
}

static int tr_fclose(FILE *fp)
{
    int rc = fclose(fp);
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"close", &g_test_close_calls))
        return EOF;
#endif
    return rc;
}

static int tr_commit(FILE *fp)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"commit", &g_test_commit_calls))
        return -1;
#endif
    return _commit(_fileno(fp));
}

static BOOL tr_move_file(const wchar_t *src, const wchar_t *dst)
{
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"move", &g_test_move_calls))
        return FALSE;
#endif
    return MoveFileExW(src, dst,
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

/* ------------------------------------------------------------ SHA-256 */

static uint32_t sha_rotr(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32u - n));
}

static void sha_transform(tr_sha256 *s, const unsigned char block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t i;

    for (i = 0; i < 16; i++) {
        size_t j = i * 4;
        w[i] = ((uint32_t)block[j] << 24) |
               ((uint32_t)block[j + 1] << 16) |
               ((uint32_t)block[j + 2] << 8) |
               (uint32_t)block[j + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t x = w[i - 15];
        uint32_t y = w[i - 2];
        uint32_t s0 = sha_rotr(x, 7) ^ sha_rotr(x, 18) ^ (x >> 3);
        uint32_t s1 = sha_rotr(y, 17) ^ sha_rotr(y, 19) ^ (y >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t s1 = sha_rotr(e, 6) ^ sha_rotr(e, 11) ^ sha_rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = sha_rotr(a, 2) ^ sha_rotr(a, 13) ^ sha_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(tr_sha256 *s)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    memset(s, 0, sizeof *s);
    memcpy(s->h, initial, sizeof initial);
}

static int sha_update(tr_sha256 *s, const void *vp, size_t n)
{
    const unsigned char *p = (const unsigned char *)vp;

    /* SHA-256's length trailer is 64-bit bits, not bytes. */
    if ((uint64_t)n > UINT64_MAX / 8u - s->total)
        return 0;
    s->total += (uint64_t)n;
    while (n) {
        size_t take = sizeof s->block - s->used;
        if (take > n)
            take = n;
        memcpy(s->block + s->used, p, take);
        s->used += take;
        p += take;
        n -= take;
        if (s->used == sizeof s->block) {
            sha_transform(s, s->block);
            s->used = 0;
        }
    }
    return 1;
}

static int sha_final_hex(const tr_sha256 *source, char out[65])
{
    tr_sha256 s = *source;
    unsigned char pad[64] = {0x80};
    unsigned char length[8];
    unsigned char digest[32];
    uint64_t bits = s.total * 8u;
    size_t pad_len = s.used < 56 ? 56 - s.used : 120 - s.used;
    size_t i;

    for (i = 0; i < 8; i++)
        length[7 - i] = (unsigned char)(bits >> (i * 8));
    /* Padding bytes are deliberately not part of source.total. */
    if (!sha_update(&s, pad, pad_len) || !sha_update(&s, length, 8))
        return 0;
    for (i = 0; i < 8; i++) {
        digest[i * 4]     = (unsigned char)(s.h[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(s.h[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(s.h[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)s.h[i];
    }
    for (i = 0; i < sizeof digest; i++) {
        out[i * 2] = HEXD[digest[i] >> 4];
        out[i * 2 + 1] = HEXD[digest[i] & 15u];
    }
    out[64] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ boot */

static BOOL CALLBACK tr_once_init(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_lock);
    g_tls = TlsAlloc();
    if (g_tls == TLS_OUT_OF_INDEXES) {
        DeleteCriticalSection(&g_lock);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    return TRUE;
}

static int tr_boot(void)
{
    if (!InitOnceExecuteOnce(&g_once, tr_once_init, NULL, NULL)) {
        recorder_fault();
        return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------- buffer */

static int buf_reserve(tr_buf *b, size_t extra)
{
    size_t want, needed;
    char *np;

    if (b->oom)
        return 0;
    if (extra > SIZE_MAX - b->len - 1) {
        b->oom = 1;
        recorder_fault();
        return 0;
    }
    needed = b->len + extra + 1;
    if (needed <= b->cap)
        return 1;
    want = b->cap ? b->cap : TR_BUF_MIN;
    while (want < needed) {
        if (want > (SIZE_MAX / 2)) {
            b->oom = 1;
            recorder_fault();
            return 0;
        }
        want *= 2;
    }
    np = b->p ? (char *)tr_heap_realloc(0, b->p, want)
              : (char *)tr_heap_alloc(0, want);
    if (!np) {
        b->oom = 1;
        recorder_fault();
        return 0;
    }
    b->p = np;
    b->cap = want;
    return 1;
}

static void buf_free(tr_buf *b)
{
    tr_heap_free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

static void buf_put(tr_buf *b, const char *s, size_t n)
{
    if (!buf_reserve(b, n))
        return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
}

static void buf_putc(tr_buf *b, char ch)
{
    if (!buf_reserve(b, 1))
        return;
    b->p[b->len++] = ch;
}

static void buf_puts(tr_buf *b, const char *s)
{
    buf_put(b, s, strlen(s));
}

static void buf_u64(tr_buf *b, unsigned long long v)
{
    char tmp[24];
    int i = 0;

    if (!v) {
        buf_putc(b, '0');
        return;
    }
    while (v) {
        tmp[i++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    while (i)
        buf_putc(b, tmp[--i]);
}

static void buf_i64(tr_buf *b, long long v)
{
    unsigned long long u;

    if (v < 0) {
        buf_putc(b, '-');
        /* Negating LLONG_MIN directly is UB. */
        u = (unsigned long long)(-(v + 1)) + 1ull;
    } else {
        u = (unsigned long long)v;
    }
    buf_u64(b, u);
}

static void buf_hex(tr_buf *b, unsigned long long v)
{
    char tmp[20];
    int i = 0;

    if (!v) {
        buf_putc(b, '0');
        return;
    }
    while (v) {
        tmp[i++] = HEXD[v & 15u];
        v >>= 4;
    }
    while (i)
        buf_putc(b, tmp[--i]);
}

static void buf_hex_fixed(tr_buf *b, unsigned long long v, int digits)
{
    while (digits-- > 0)
        buf_putc(b, HEXD[(v >> (digits * 4)) & 15u]);
}

static void buf_f64(tr_buf *b, double v)
{
    char raw[48];
    int n, i;
    char prev = 0;
    int fractional = 0;

    /* Non-finite values have no RFC 8259 representation.  Emitting a Python
       JSON extension here could make two unrepresentable values look equal,
       so invalidate the whole recording instead. */
    if (isnan(v)) {
        b->oom = 1;
        recorder_fault();
        return;
    }
    if (isinf(v)) {
        b->oom = 1;
        recorder_fault();
        return;
    }
    n = snprintf(raw, sizeof raw, "%.17g", v);
    if (n <= 0 || (size_t)n >= sizeof raw) {
        b->oom = 1;
        recorder_fault();
        return;
    }
    for (i = 0; i < n; i++) {
        char ch = raw[i];
        int keep = (ch >= '0' && ch <= '9') || ch == '-' || ch == '+' ||
                   ch == 'e' || ch == 'E';
        if (!keep) {
            /* Whatever the locale used as a decimal separator, possibly more
               than one byte of it, collapses to a single '.'. */
            if (prev == '.')
                continue;
            ch = '.';
        }
        if (ch == '.' || ch == 'e' || ch == 'E')
            fractional = 1;
        buf_putc(b, ch);
        prev = ch;
    }
    /* "%.17g" prints a whole-numbered double with neither a point nor an
       exponent ("2", "-0"). json.loads would then hand the reader an int,
       so an f64 field would sometimes be int and sometimes float, and -0.0
       would arrive indistinguishable from 0.0 -- a real IEEE difference
       between the old DLL and the shim silently matching. */
    if (!fractional)
        buf_puts(b, ".0");
}

/* Emits a quoted JSON string. Bytes that are not valid UTF-8 become an
   explicit U+FFFD escape instead of leaking raw into a file the reader opens
   as UTF-8. */
static void json_str(tr_buf *b, const char *s, size_t n)
{
    size_t i = 0;

    buf_putc(b, '"');
    while (i < n) {
        unsigned char ch = (unsigned char)s[i];
        size_t need, k;
        unsigned int cp;
        int ok;

        if (ch < 0x80u) {
            switch (ch) {
            case '"':  buf_put(b, "\\\"", 2); break;
            case '\\': buf_put(b, "\\\\", 2); break;
            case '\b': buf_put(b, "\\b", 2); break;
            case '\f': buf_put(b, "\\f", 2); break;
            case '\n': buf_put(b, "\\n", 2); break;
            case '\r': buf_put(b, "\\r", 2); break;
            case '\t': buf_put(b, "\\t", 2); break;
            default:
                if (ch < 0x20u) {
                    char u[6];
                    u[0] = '\\'; u[1] = 'u'; u[2] = '0'; u[3] = '0';
                    u[4] = HEXD[ch >> 4]; u[5] = HEXD[ch & 15u];
                    buf_put(b, u, 6);
                } else {
                    buf_putc(b, (char)ch);
                }
            }
            i++;
            continue;
        }

        if ((ch & 0xE0u) == 0xC0u)      { need = 2; cp = ch & 0x1Fu; }
        else if ((ch & 0xF0u) == 0xE0u) { need = 3; cp = ch & 0x0Fu; }
        else if ((ch & 0xF8u) == 0xF0u) { need = 4; cp = ch & 0x07u; }
        else {
            /* Replacement would collapse distinct invalid byte sequences. */
            recorder_fault();
            b->oom = 1;
            return;
        }

        if (i + need > n) {
            recorder_fault();
            b->oom = 1;
            return;
        }
        ok = 1;
        for (k = 1; k < need; k++) {
            unsigned char cc = (unsigned char)s[i + k];
            if ((cc & 0xC0u) != 0x80u) {
                ok = 0;
                break;
            }
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        /* Overlongs, surrogates and out-of-range code points are as invalid
           as a stray continuation byte. */
        if (!ok ||
            (need == 2 && cp < 0x80u) ||
            (need == 3 && cp < 0x800u) ||
            (need == 4 && cp < 0x10000u) ||
            cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
            recorder_fault();
            b->oom = 1;
            return;
        }
        buf_put(b, s + i, need);
        i += need;
    }
    buf_putc(b, '"');
}

static void put_key(tr_buf *b, const char *name)
{
    json_str(b, name ? name : "", name ? strlen(name) : 0);
    buf_putc(b, ':');
}

/* ----------------------------------------------------- guarded memory io */

static size_t readable_span(const void *p, size_t want)
{
    const unsigned char *cur = (const unsigned char *)p;
    const unsigned char *end;
    MEMORY_BASIC_INFORMATION mbi;
    size_t ok = 0;

    if (!p || !want || want > UINTPTR_MAX - (uintptr_t)cur)
        return 0;
    end = cur + want;
    while (cur < end) {
        const unsigned char *rend;
        size_t chunk;

        if (VirtualQuery(cur, &mbi, sizeof mbi) != sizeof mbi)
            break;
        if (mbi.State != MEM_COMMIT)
            break;
        if (mbi.Protect & PAGE_GUARD)   /* touching it would arm a stack grow */
            break;
        if (!(mbi.Protect & TR_READABLE))
            break;
        rend = (const unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (rend <= cur)
            break;
        chunk = (size_t)((rend < end ? rend : end) - cur);
        ok += chunk;
        cur += chunk;
    }
    return ok;
}

static __declspec(noinline) void copy_worker(void *dst, const void *src, size_t n)
{
    memcpy(dst, src, n);
}

static __declspec(noinline) void hex_worker(char *dst, const unsigned char *src,
                                            size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char v = src[i];
        dst[2 * i]     = HEXD[v >> 4];
        dst[2 * i + 1] = HEXD[v & 15u];
    }
}

static __declspec(noinline) size_t scan8_worker(const char *s, size_t max)
{
    size_t i = 0;

    while (i < max && s[i] != '\0')
        i++;
    return i;
}

static __declspec(noinline) size_t scan16_worker(const unsigned short *s,
                                                 size_t max)
{
    size_t i = 0;

    while (i < max && s[i] != 0)
        i++;
    return i;
}

static __declspec(noinline) int w2u8_worker(const unsigned short *s, int cch,
                                            char *dst, int cb)
{
    return WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)s, cch, dst, cb, NULL, NULL);
}

static int guard_copy(void *dst, const void *src, size_t n)
{
    volatile int ok = 1;
#if TR_SEH
    __try {
        copy_worker(dst, src, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
#else
    copy_worker(dst, src, n);
#endif
    return ok;
}

static int guard_hex(char *dst, const void *src, size_t n)
{
    volatile int ok = 1;
#if TR_SEH
    __try {
        hex_worker(dst, (const unsigned char *)src, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
#else
    hex_worker(dst, (const unsigned char *)src, n);
#endif
    return ok;
}

static int guard_scan8(const char *s, size_t max, size_t *out)
{
    volatile size_t got = 0;
    volatile int ok = 1;
#if TR_SEH
    __try {
        got = scan8_worker(s, max);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
#else
    got = scan8_worker(s, max);
#endif
    if (ok)
        *out = got;
    return ok;
}

static int guard_scan16(const unsigned short *s, size_t max, size_t *out)
{
    volatile size_t got = 0;
    volatile int ok = 1;
#if TR_SEH
    __try {
        got = scan16_worker(s, max);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
#else
    got = scan16_worker(s, max);
#endif
    if (ok)
        *out = got;
    return ok;
}

static int guard_w2u8(const unsigned short *s, int cch, char *dst, int cb,
                      int *out)
{
    volatile int got = 0;
    volatile int ok = 1;
#if TR_SEH
    __try {
        got = w2u8_worker(s, cch, dst, cb);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
#else
    got = w2u8_worker(s, cch, dst, cb);
#endif
    if (ok)
        *out = got;
    return ok;
}

/* ------------------------------------------------------------------ sink */

static int sink_line(const char *p, size_t n)
{
    int ok = 0;

    EnterCriticalSection(&g_lock);
    if (g_fp) {
        ok = tr_fwrite(p, 1, n, g_fp) == n;
        /* Per line: a run that dies mid-scenario still yields every record
           that completed before the crash. */
        if (ok)
            ok = tr_fflush(g_fp) == 0 && !ferror(g_fp);
        if (ok) {
            if (g_payload_records == UINT64_MAX ||
                !sha_update(&g_sha, p, n)) {
                ok = 0;
            } else {
                g_payload_records++;
            }
        }
    }
    if (!ok)
        recorder_fault();
    LeaveCriticalSection(&g_lock);
    return ok;
}

void tr_note(const char *sym, const char *msg)
{
    tr_buf b;
    LONG seq;

    /* Participate in the same shutdown barrier as call frames.  Without this
       claim, shutdown could commit a footer after the ready check but before
       this diagnostic makes the recorder sticky-faulted. */
    InterlockedIncrement(&g_inflight);
    if (!InterlockedCompareExchange(&g_ready, 0, 0)) {
        InterlockedDecrement(&g_inflight);
        return;
    }
    /* Notes are not admissible evidence.  Keep the diagnostic line when
       possible, but make the normal-completion footer impossible. */
    recorder_fault();
    memset(&b, 0, sizeof b);
    seq = InterlockedIncrement(&g_seq);
    if (seq <= 0)
        recorder_fault();
    buf_puts(&b, "{\"t\":\"n\",\"q\":");
    buf_i64(&b, seq);
    buf_puts(&b, ",\"s\":");
    json_str(&b, sym ? sym : "", sym ? strlen(sym) : 0);
    buf_puts(&b, ",\"msg\":");
    json_str(&b, msg ? msg : "", msg ? strlen(msg) : 0);
    buf_puts(&b, "}\n");
    if (!b.oom)
        (void)sink_line(b.p, b.len);
    else
        recorder_fault();
    buf_free(&b);
    InterlockedDecrement(&g_inflight);
}

/* Recorder-internal diagnostics are budgeted: a loop over 1 MiB buffers
   would otherwise double the size of the trace with identical notes. */
static void note_lim(const char *sym, const char *msg)
{
    LONG left = InterlockedDecrement(&g_note_budget);

    recorder_fault();
    if (left < 0)
        return;
    tr_note(sym, msg);
    if (left == 0)
        tr_note("", "recorder notes suppressed past budget");
}

/* ---------------------------------------------------------- thread state */

static tr_thread *ts_get(void)
{
    tr_thread *ts;
    DWORD tls_error;

    if (g_tls == TLS_OUT_OF_INDEXES) {
        recorder_fault();
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    ts = (tr_thread *)TlsGetValue(g_tls);
    tls_error = GetLastError();
    if (ts)
        return ts;
    if (tls_error != ERROR_SUCCESS) {
        recorder_fault();
        return NULL;
    }
    ts = (tr_thread *)tr_heap_alloc(HEAP_ZERO_MEMORY, sizeof *ts);
    if (!ts) {
        recorder_fault();
        return NULL;
    }
#ifdef TR_TEST_FAULT_INJECT
    if (test_fail(L"tls", &g_test_tls_calls) || !TlsSetValue(g_tls, ts)) {
#else
    if (!TlsSetValue(g_tls, ts)) {
#endif
        tr_heap_free(ts);
        recorder_fault();
        return NULL;
    }
    EnterCriticalSection(&g_lock);
    ts->next = g_threads;
    g_threads = ts;
    LeaveCriticalSection(&g_lock);
    return ts;
}

/* --------------------------------------------------------------- open/io */

static int utf8_to_wide_fixed(const char *s, wchar_t *out, size_t cap)
{
    int need;

    if (!s || !*s || cap > (size_t)INT_MAX)
        return 0;
    need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1,
                               NULL, 0);
    if (need <= 0 || (size_t)need > cap)
        return 0;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1,
                            out, (int)cap) != need)
        return 0;
    return 1;
}

static wchar_t *wide_dup(const wchar_t *s)
{
    size_t n;
    wchar_t *out;

    if (!s)
        return NULL;
    n = wcslen(s);
    if (n > (SIZE_MAX / sizeof *out) - 1) {
        recorder_fault();
        return NULL;
    }
    out = (wchar_t *)tr_heap_alloc(0, (n + 1) * sizeof *out);
    if (!out) {
        recorder_fault();
        return NULL;
    }
    memcpy(out, s, (n + 1) * sizeof *out);
    return out;
}

static char *wide_to_utf8(const wchar_t *s)
{
    char *out;
    int need;

    if (!s || !*s)
        return NULL;
    need = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s, -1,
                               NULL, 0, NULL, NULL);
    if (need <= 0)
        return NULL;
    out = (char *)tr_heap_alloc(0, (size_t)need);
    if (!out) {
        recorder_fault();
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s, -1,
                            out, need, NULL, NULL) != need) {
        tr_heap_free(out);
        recorder_fault();
        return NULL;
    }
    return out;
}

/* Allocation-free control read used for TAP_TRACE and TAP_PASSTHROUGH.  It
   lets tr_init invalidate stale evidence before any fallible heap operation.
   Windows environment values cannot exceed TR_ENV_MAX_CHARS. */
static int env_wread_fixed(const wchar_t *name, wchar_t *out, DWORD cap)
{
    DWORD n, err;

    if (!out || cap == 0)
        return -1;
    SetLastError(ERROR_SUCCESS);
    n = GetEnvironmentVariableW(name, out, cap);
    if (!n) {
        err = GetLastError();
        out[0] = L'\0';
        return (err == ERROR_SUCCESS || err == ERROR_ENVVAR_NOT_FOUND) ? 0 : -1;
    }
    if (n >= cap) {
        out[0] = L'\0';
        return -1;
    }
    return 1;
}

/* Returns 1 with an allocated value, 0 when absent/empty, and -1 on an
   invalid, oversized, racing, or unallocatable value. Size-query followed by
   bounded retry is required: GetEnvironmentVariable's "buffer too small"
   return is a REQUIRED length, not bytes stored in the caller's buffer. */
static int env_wdup(const wchar_t *name, wchar_t **out)
{
    DWORD cap, n, err;
    int attempt;

    *out = NULL;
    SetLastError(ERROR_SUCCESS);
    cap = GetEnvironmentVariableW(name, NULL, 0);
    if (!cap) {
        err = GetLastError();
        return (err == ERROR_SUCCESS || err == ERROR_ENVVAR_NOT_FOUND) ? 0 : -1;
    }
    for (attempt = 0; attempt < TR_ENV_RETRIES; attempt++) {
        wchar_t *p;

        if (cap > TR_ENV_MAX_CHARS)
            return -1;
        p = (wchar_t *)tr_heap_alloc(0, (size_t)cap * sizeof *p);
        if (!p) {
            recorder_fault();
            return -1;
        }
        SetLastError(ERROR_SUCCESS);
        n = GetEnvironmentVariableW(name, p, cap);
        if (n > 0 && n < cap) {
            *out = p;
            return 1;
        }
        err = GetLastError();
        tr_heap_free(p);
        if (!n)
            return (err == ERROR_SUCCESS || err == ERROR_ENVVAR_NOT_FOUND) ? 0 : -1;
        cap = n;                 /* required size includes the terminator */
    }
    return -1;
}

static int parse_wsize(const wchar_t *s, size_t *out)
{
    size_t v = 0;

    if (!s || *s < L'0' || *s > L'9')
        return 0;
    while (*s) {
        if (*s < L'0' || *s > L'9' || v > (SIZE_MAX - 9) / 10)
            return 0;
        v = v * 10 + (size_t)(*s - L'0');
        s++;
    }
    *out = v;
    return 1;
}

static int parse_sha256(const wchar_t *s, char out[65])
{
    size_t i, len = 0;

    if (!s)
        return 0;
    while (len <= 64 && s[len])
        len++;
    if (len != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        wchar_t ch = s[i];

        if (ch >= L'0' && ch <= L'9')
            out[i] = (char)ch;
        else if (ch >= L'a' && ch <= L'f')
            out[i] = (char)ch;
        else if (ch >= L'A' && ch <= L'F')
            out[i] = (char)(ch - L'A' + L'a');
        else
            return 0;
    }
    out[64] = '\0';
    return 1;
}

static wchar_t *make_partial_path(const wchar_t *final_path)
{
    size_t n;
    wchar_t *out;
    int wrote;
    LONG nonce = InterlockedIncrement(&g_temp_nonce);

    if (!final_path)
        return NULL;
    n = wcslen(final_path);
    if (n > TR_ENV_MAX_CHARS - 48) {
        recorder_fault();
        return NULL;
    }
    out = (wchar_t *)tr_heap_alloc(0, (n + 48) * sizeof *out);
    if (!out) {
        recorder_fault();
        return NULL;
    }
    wrote = _snwprintf_s(out, n + 48, _TRUNCATE,
                         L"%ls.partial.%lu.%ld", final_path,
                         (unsigned long)GetCurrentProcessId(), (long)nonce);
    if (wrote < 0) {
        tr_heap_free(out);
        recorder_fault();
        return NULL;
    }
    return out;
}

/* Remove any previously valid evidence before recording starts.  The actual
   run is written to a sibling partial and atomically replaces this empty
   sentinel only after footer/write/flush/commit/close all succeed. */
static int invalidate_final_path(const wchar_t *path)
{
    HANDLE h;
    int ok;

    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        recorder_fault();
        return 0;
    }
    ok = FlushFileBuffers(h) != 0;
    if (!CloseHandle(h))
        ok = 0;
    if (!ok)
        recorder_fault();
    return ok;
}

void tr_init(const char *path, const char *module, const char *arch,
             const char *label, const char *contract_sha256)
{
    wchar_t *env_label = NULL;
    wchar_t *env_maxcap = NULL;
    wchar_t *env_subject = NULL;
    char *label_utf8 = NULL;
    char subject_hex[65];
    int pass_status, path_status, label_status, maxcap_status, subject_status;
    int have_subject = 0;
    const char *use_label = label;
    size_t parsed_maxcap;
    tr_buf b;

    if (!tr_boot())
        return;
    EnterCriticalSection(&g_lock);
    if (g_started) {
        LeaveCriticalSection(&g_lock);
        return;
    }
    g_started = 1;

    pass_status = env_wread_fixed(L"TAP_PASSTHROUGH", g_env_pass,
                                  (DWORD)(sizeof g_env_pass /
                                          sizeof g_env_pass[0]));
    path_status = env_wread_fixed(L"TAP_TRACE", g_env_path,
                                  (DWORD)(sizeof g_env_path /
                                          sizeof g_env_path[0]));
    if (pass_status > 0 && !wcscmp(g_env_pass, L"1")) {
        /* The same binary serves the passthrough oracle check, so this has to
           mean "no file, no seq, no per-thread state", not "record quietly". */
        goto done;
    }

    if (path_status == 0 && path && *path) {
        /* The API contract for tr_init is UTF-8. Never silently reinterpret a
           malformed path through the process ANSI codepage. */
        if (!utf8_to_wide_fixed(path, g_env_path,
                                sizeof g_env_path / sizeof g_env_path[0]))
            path_status = -1;
        else
            path_status = 1;
    }
    if (path_status > 0) {
        /* Do this before the first fallible heap allocation.  Even an OOM in
           control parsing then leaves an empty, inadmissible authoritative
           path instead of stale evidence from a previous process. */
        if (!invalidate_final_path(g_env_path))
            goto done;
        g_final_path = wide_dup(g_env_path);
        if (!g_final_path)
            goto done;
    }
    if (pass_status < 0 || path_status < 0 || !g_final_path) {
        recorder_fault();
        goto done;
    }

    label_status = env_wdup(L"TAP_LABEL", &env_label);
    maxcap_status = env_wdup(L"TAP_MAXCAP", &env_maxcap);
    subject_status = env_wdup(L"TAP_SUBJECT_SHA256", &env_subject);
    if (label_status < 0 || maxcap_status < 0 || subject_status < 0)
        goto done;

    if (label_status > 0) {
        label_utf8 = wide_to_utf8(env_label);
        if (!label_utf8)
            goto done;
        use_label = label_utf8;
    }
    if (maxcap_status > 0) {
        if (!parse_wsize(env_maxcap, &parsed_maxcap))
            goto done;
        g_maxcap = parsed_maxcap;
    }
    if (subject_status > 0)
        have_subject = parse_sha256(env_subject, subject_hex);

    g_partial_path = make_partial_path(g_final_path);
    if (!g_partial_path)
        goto done;
    g_fp = _wfopen(g_partial_path, L"wb");
    if (!g_fp) {
        recorder_fault();
        goto done;
    }

    sha_init(&g_sha);
    g_payload_records = 0;
    memset(&b, 0, sizeof b);
    buf_puts(&b, "{\"t\":\"hdr\",\"v\":");
    buf_u64(&b, TR_WIRE_VERSION);
    buf_puts(&b, ",\"module\":");
    json_str(&b, module ? module : "", module ? strlen(module) : 0);
    buf_puts(&b, ",\"arch\":");
    json_str(&b, arch ? arch : "x64", arch ? strlen(arch) : 3);
    buf_puts(&b, ",\"pid\":");
    buf_u64(&b, GetCurrentProcessId());
    buf_puts(&b, ",\"run\":\"");
    {
        /* Distinguishes two runs of the same scenario in the same directory;
           it is not compared, so a cheap mix is enough. */
        unsigned long long mix = (unsigned long long)GetCurrentProcessId() *
                                 2654435761ull;
        mix ^= GetTickCount64() * 1099511628211ull;
        mix ^= (unsigned long long)(uintptr_t)&g_lock;
        buf_hex_fixed(&b, (mix >> 16) & 0xFFFFFFFFull, 8);
    }
    buf_puts(&b, "\",\"tap\":\"" TR_TAP_VERSION "\"");
    buf_puts(&b, ",\"maxcap\":");
    buf_u64(&b, (unsigned long long)g_maxcap);
    if (contract_sha256 && *contract_sha256) {
        buf_puts(&b, ",\"contract\":");
        json_str(&b, contract_sha256, strlen(contract_sha256));
    }
    if (have_subject) {
        buf_puts(&b, ",\"subject\":");
        json_str(&b, subject_hex, 64);
    }
    if (use_label && *use_label) {
        buf_puts(&b, ",\"label\":");
        json_str(&b, use_label, strlen(use_label));
    }
    buf_puts(&b, "}\n");
    if (!b.oom && !recorder_is_faulted() &&
        tr_fwrite(b.p, 1, b.len, g_fp) == b.len &&
        tr_fflush(g_fp) == 0 && !ferror(g_fp) &&
        sha_update(&g_sha, b.p, b.len)) {
        InterlockedExchange(&g_ready, 1);
    } else {
        recorder_fault();
        (void)tr_fflush(g_fp);
        (void)tr_commit(g_fp);
        if (tr_fclose(g_fp) != 0)
            recorder_fault();
        g_fp = NULL;
    }
    buf_free(&b);
done:
    tr_heap_free(env_label);
    tr_heap_free(env_maxcap);
    tr_heap_free(env_subject);
    tr_heap_free(label_utf8);
    LeaveCriticalSection(&g_lock);
}

void tr_shutdown(void)
{
    tr_thread *ts, *next;
    int quiescent;
    int close_ok = 1;
    tr_buf footer;
    char digest[65];

    if (!g_started)
        return;
    if (!tr_boot())
        return;
    EnterCriticalSection(&g_lock);
    InterlockedExchange(&g_ready, 0);
    quiescent = InterlockedCompareExchange(&g_inflight, 0, 0) == 0;
    if (!quiescent)
        recorder_fault();
    /* Per-thread blocks are only reclaimed when no frame can still be holding
       one. The lock and the TLS index are deliberately kept: another thread
       may be parked on either, and leaking two handles at teardown is
       cheaper than a race. */
    if (quiescent) {
        for (ts = g_threads; ts; ts = next) {
            int i;

            next = ts->next;
            for (i = 0; i < TR_MAX_DEPTH; i++)
                buf_free(&ts->slots[i].b);
            buf_free(&ts->scratch);
            tr_heap_free(ts);
        }
        g_threads = NULL;
        if (g_tls != TLS_OUT_OF_INDEXES && !TlsSetValue(g_tls, NULL))
            recorder_fault();
    }
    if (g_fp) {
        /* The footer is an assertion, not best-effort logging.  It is written
           only when every prior operation remained lossless. */
        if (quiescent && !recorder_is_faulted()) {
            memset(&footer, 0, sizeof footer);
            if (!sha_final_hex(&g_sha, digest)) {
                recorder_fault();
            } else {
                buf_puts(&footer, "{\"t\":\"end\",\"records\":");
                buf_u64(&footer, g_payload_records);
                buf_puts(&footer, ",\"bytes\":");
                buf_u64(&footer, g_sha.total);
                buf_puts(&footer, ",\"sha256\":\"");
                buf_put(&footer, digest, 64);
                buf_puts(&footer, "\"}\n");
            }
            if (footer.oom || recorder_is_faulted() ||
                tr_fwrite(footer.p, 1, footer.len, g_fp) != footer.len ||
                tr_fflush(g_fp) != 0 || ferror(g_fp)) {
                recorder_fault();
                close_ok = 0;
            }
            buf_free(&footer);
        }
        /* _commit reaches the storage device before close.  fclose is still
           checked independently; the partial is never promoted when either
           operation reports failure. */
        if (tr_fflush(g_fp) != 0 || ferror(g_fp) || tr_commit(g_fp) != 0) {
            recorder_fault();
            close_ok = 0;
        }
        if (tr_fclose(g_fp) != 0) {
            recorder_fault();
            close_ok = 0;
        }
        g_fp = NULL;

        /* On a recorder fault, promoting a successfully closed *incomplete*
           partial is intentional: callers get diagnostics at the requested
           path, while the missing footer makes it inadmissible.  A fully
           formed trace is promoted only after close succeeded. */
        if (close_ok && g_partial_path && g_final_path) {
            if (!tr_move_file(g_partial_path, g_final_path))
                recorder_fault();
        }
    }
    tr_heap_free(g_final_path);
    tr_heap_free(g_partial_path);
    g_final_path = NULL;
    g_partial_path = NULL;
    LeaveCriticalSection(&g_lock);
}

int tr_enabled(void)
{
    return InterlockedCompareExchange(&g_ready, 0, 0) != 0;
}

/* --------------------------------------------------------- record layout */

static void reset_call(tr_call *c, tr_thread *ts)
{
    tr_buf keep = c->b;
    int heap = c->heap;

    keep.len = 0;
    keep.oom = 0;
    memset(c, 0, sizeof *c);
    c->b = keep;                /* the frame buffer is reused, never reshrunk */
    c->heap = heap;
    c->ts = ts;
}

tr_call *tr_enter(const char *sym, int is_callback)
{
    tr_thread *ts;
    tr_call *c;
    LONG seq;
    int idx;

    /* Claimed before the g_ready test so that tr_shutdown cannot free a
       thread block out from under a frame that is just starting. */
    InterlockedIncrement(&g_inflight);
    if (!InterlockedCompareExchange(&g_ready, 0, 0)) {
        InterlockedDecrement(&g_inflight);
        return NULL;
    }
    ts = ts_get();
    if (!ts) {
        InterlockedDecrement(&g_inflight);
        return NULL;
    }

    idx = ts->depth;
    if (idx < TR_MAX_DEPTH) {
        c = &ts->slots[idx];
        reset_call(c, ts);
    } else {
        /* Past the fixed stack the record is still emitted: dropping it would
           read downstream as a missing-call divergence, which is worse than a
           clamped parent link. */
        c = (tr_call *)tr_heap_alloc(HEAP_ZERO_MEMORY, sizeof *c);
        if (!c) {
            recorder_fault();
            InterlockedDecrement(&g_inflight);
            return NULL;
        }
        c->heap = 1;
        c->ts = ts;
        if (!ts->overflow_noted) {
            ts->overflow_noted = 1;
            note_lim(sym, "call depth past TR_MAX_DEPTH; parent links clamped");
        }
    }

    c->sym = sym ? sym : "";
    seq = InterlockedIncrement(&g_seq);
    if (seq <= 0)
        recorder_fault();
    c->seq = seq;
    c->depth = ts->depth;
    if (idx > 0) {
        c->has_parent = 1;
        c->parent = ts->stack[(idx < TR_MAX_DEPTH ? idx : TR_MAX_DEPTH) - 1];
    }
    if (idx < TR_MAX_DEPTH)
        ts->stack[idx] = seq;
    ts->depth++;

    buf_puts(&c->b, is_callback ? "{\"t\":\"k\",\"q\":" : "{\"t\":\"c\",\"q\":");
    buf_i64(&c->b, seq);
    buf_puts(&c->b, ",\"d\":");
    buf_u64(&c->b, GetCurrentThreadId());
    buf_puts(&c->b, ",\"dp\":");
    buf_i64(&c->b, c->depth);
    buf_puts(&c->b, ",\"s\":");
    json_str(&c->b, c->sym, strlen(c->sym));
    buf_puts(&c->b, ",\"p\":");
    if (c->has_parent)
        buf_i64(&c->b, c->parent);
    else
        buf_puts(&c->b, "null");
    return c;
}

/* Opens the right section, writes the separator and the member key. Returns 0
   when the member cannot be placed. */
static int begin_member(tr_call *c, int out, const char *name)
{
    if (!c || c->b.oom)
        return 0;
    if (!out) {
        if (c->section >= 2) {
            /* "in" is already closed; reopening would put the member in the
               wrong bucket, which is a worse lie than losing it. */
            note_lim(c->sym, "in-arg logged after an out-arg; dropped");
            return 0;
        }
        if (c->section == 0) {
            buf_puts(&c->b, ",\"in\":{");
            c->section = 1;
            c->items = 0;
        } else if (c->items) {
            buf_putc(&c->b, ',');
        }
    } else {
        if (c->section == 0) {
            buf_puts(&c->b, ",\"in\":{},\"out\":{");
            c->section = 2;
            c->items = 0;
        } else if (c->section == 1) {
            buf_puts(&c->b, "},\"out\":{");
            c->section = 2;
            c->items = 0;
        } else if (c->items) {
            buf_putc(&c->b, ',');
        }
    }
    c->items++;
    put_key(&c->b, name);
    return 1;
}

/* Fixed-width kinds are normalized so that a thunk that sign-extends and one
   that zero-extends produce the same record. */
static void put_scalar(tr_buf *b, long long v, const char *k)
{
    unsigned long long u = (unsigned long long)v;

    if (!strcmp(k, "u8"))        buf_u64(b, u & 0xFFull);
    else if (!strcmp(k, "u16"))  buf_u64(b, u & 0xFFFFull);
    else if (!strcmp(k, "u32"))  buf_u64(b, u & 0xFFFFFFFFull);
    else if (!strcmp(k, "u64"))  buf_u64(b, u);
    else if (!strcmp(k, "bool")) buf_putc(b, v ? '1' : '0');
    else if (!strcmp(k, "i8"))   buf_i64(b, (signed char)(u & 0xFFull));
    else if (!strcmp(k, "i16"))  buf_i64(b, (short)(u & 0xFFFFull));
    else if (!strcmp(k, "i32"))  buf_i64(b, (int)(unsigned int)u);
    else                         buf_i64(b, v);
}

static void emit_i64(tr_buf *b, long long v, const char *kind)
{
    const char *k = (kind && *kind) ? kind : "i64";

    buf_puts(b, "{\"k\":");
    json_str(b, k, strlen(k));
    buf_puts(b, ",\"v\":");
    put_scalar(b, v, k);
    buf_putc(b, '}');
}

static void emit_f64(tr_buf *b, double v)
{
    buf_puts(b, "{\"k\":\"f64\",\"v\":");
    buf_f64(b, v);
    buf_putc(b, '}');
}

static void emit_ptr(tr_call *c, const void *p, long long nbytes)
{
    tr_buf *b = &c->b;
    size_t want, cap, span, mark;
    int truncated = 0;

    buf_puts(b, "{\"k\":\"ptr\",\"p\":\"");
    buf_hex(b, (unsigned long long)(uintptr_t)p);
    buf_putc(b, '"');
    if (!p) {
        buf_putc(b, '}');
        return;
    }
    if (nbytes < 0) {
        /* Declared unknown extent: n=0 with no b says "not looked at". */
        buf_puts(b, ",\"n\":0}");
        recorder_fault();
        return;
    }
    if ((unsigned long long)nbytes > (unsigned long long)SIZE_MAX) {
        b->oom = 1;
        recorder_fault();
        return;
    }

    want = (size_t)nbytes;
    buf_puts(b, ",\"n\":");
    buf_u64(b, want);           /* attempted, before any clamping */
    if (want == 0) {
        buf_puts(b, ",\"b\":\"\"}");
        return;
    }

    cap = want;
    if (cap > g_maxcap) {
        cap = g_maxcap;
        truncated = 1;
    }
    span = cap ? readable_span(p, cap) : 0;
    if (span) {
        mark = b->len;
        buf_puts(b, ",\"b\":\"");
        if (span <= (SIZE_MAX - 4) / 2 &&
            buf_reserve(b, span * 2 + 4) &&
            guard_hex(b->p + b->len, p, span)) {
            b->len += span * 2;
            buf_putc(b, '"');
        } else {
            /* Freed between the probe and the read: drop the whole b member
               rather than emit half a byte string. */
            b->len = mark;
            span = 0;
            recorder_fault();
        }
    }
    if (!span && cap)
        note_lim(c->sym, "pointer capture faulted; bytes not recorded");
    else if (span && span < cap)
        note_lim(c->sym, "pointer capture short: unreadable tail");
    if (truncated)
        note_lim(c->sym, "pointer capture truncated at TAP_MAXCAP");
    buf_putc(b, '}');
}

/* Decodes into the per-thread scratch first so the JSON escaper only ever
   walks memory this module owns. Returns the decoded length, or -1. */
static long long decode_str(tr_call *c, const void *p, int wide)
{
    tr_thread *ts = c->ts;
    size_t span, len, need;

    if (!ts || g_maxcap == 0)
        return -1;
    ts->scratch.len = 0;

    if (!wide) {
        span = readable_span(p, g_maxcap);
        if (!span || !guard_scan8((const char *)p, span, &len))
            return -1;
        if (len == span)
            note_lim(c->sym, "string not terminated inside the capture window");
        if (!buf_reserve(&ts->scratch, len + 1) ||
            !guard_copy(ts->scratch.p, p, len))
            return -1;
        return (long long)len;
    } else {
        size_t maxchars = g_maxcap / 2;
        int got = 0;

        if (!maxchars)
            return -1;
        span = readable_span(p, maxchars * 2) / 2;
        if (!span || !guard_scan16((const unsigned short *)p, span, &len))
            return -1;
        if (len == span)
            note_lim(c->sym, "string not terminated inside the capture window");
        if (len == 0)
            return 0;
        if (len > (SIZE_MAX - 4) / 3 || len > (size_t)INT_MAX) {
            recorder_fault();
            return -1;
        }
        need = len * 3 + 4;     /* worst case for UTF-16 -> UTF-8 per unit */
        if (need > (size_t)INT_MAX) {
            recorder_fault();
            return -1;
        }
        if (!buf_reserve(&ts->scratch, need))
            return -1;
        if (!guard_w2u8((const unsigned short *)p, (int)len, ts->scratch.p,
                        (int)need, &got) || got <= 0)
            return -1;
        return got;
    }
}

static void emit_str(tr_call *c, const void *p, int wide)
{
    tr_buf *b = &c->b;
    long long n;

    /* Key order follows trace.Val.to_json(): k, v, p. */
    buf_puts(b, wide ? "{\"k\":\"wstr\"" : "{\"k\":\"str\"");
    if (p) {
        n = decode_str(c, p, wide);
        if (n < 0) {
            note_lim(c->sym, "string capture faulted; text not recorded");
        } else {
            buf_puts(b, ",\"v\":");
            json_str(b, c->ts->scratch.p ? c->ts->scratch.p : "", (size_t)n);
        }
    }
    buf_puts(b, ",\"p\":\"");
    buf_hex(b, (unsigned long long)(uintptr_t)p);
    buf_puts(b, "\"}");
}

/* --------------------------------------------------------- public logging */

void tr_in_i64(tr_call *c, const char *name, long long v, const char *kind)
{
    if (begin_member(c, 0, name))
        emit_i64(&c->b, v, kind);
}

void tr_in_f64(tr_call *c, const char *name, double v)
{
    if (begin_member(c, 0, name))
        emit_f64(&c->b, v);
}

void tr_in_ptr(tr_call *c, const char *name, const void *p, long long nbytes)
{
    if (begin_member(c, 0, name))
        emit_ptr(c, p, nbytes);
}

void tr_in_str(tr_call *c, const char *name, const char *s)
{
    if (begin_member(c, 0, name))
        emit_str(c, s, 0);
}

void tr_in_wstr(tr_call *c, const char *name, const unsigned short *s)
{
    if (begin_member(c, 0, name))
        emit_str(c, s, 1);
}

void tr_out_i64(tr_call *c, const char *name, long long v, const char *kind)
{
    if (begin_member(c, 1, name))
        emit_i64(&c->b, v, kind);
}

void tr_out_f64(tr_call *c, const char *name, double v)
{
    if (begin_member(c, 1, name))
        emit_f64(&c->b, v);
}

void tr_out_ptr(tr_call *c, const char *name, const void *p, long long nbytes)
{
    if (begin_member(c, 1, name))
        emit_ptr(c, p, nbytes);
}

void tr_out_str(tr_call *c, const char *name, const char *s)
{
    if (begin_member(c, 1, name))
        emit_str(c, s, 0);
}

void tr_out_wstr(tr_call *c, const char *name, const unsigned short *s)
{
    if (begin_member(c, 1, name))
        emit_str(c, s, 1);
}

/* The return value is buffered rather than written straight through, so a
   thunk that logs the return before its out-args still emits valid JSON. */
void tr_ret_i64(tr_call *c, long long v, const char *kind)
{
    const char *k = (kind && *kind) ? kind : "i64";
    size_t n;

    if (!c)
        return;
    n = strlen(k);
    if (n >= sizeof c->ret_k) {
        recorder_fault();
        return;
    }
    memcpy(c->ret_k, k, n);
    c->ret_k[n] = '\0';
    c->ret_i = v;
    c->ret_kind = 1;
}

void tr_ret_f64(tr_call *c, double v)
{
    if (!c)
        return;
    c->ret_f = v;
    c->ret_kind = 2;
}

void tr_ret_void(tr_call *c)
{
    if (!c)
        return;
    /* Recorded explicitly: "returned void" and "the thunk forgot to log a
       return" must not look the same to the differ. */
    c->ret_kind = 3;
}

void tr_lasterr(tr_call *c, unsigned long err)
{
    if (!c)
        return;
    c->err = err;
    c->has_err = 1;
}

void tr_leave(tr_call *c)
{
    tr_thread *ts;
    tr_buf *b;

    if (!c)
        return;
    b = &c->b;

    if (c->section == 0)
        buf_puts(b, ",\"in\":{},\"out\":{}");
    else if (c->section == 1)
        buf_puts(b, "},\"out\":{}");
    else
        buf_putc(b, '}');

    if (c->ret_kind == 1) {
        buf_puts(b, ",\"r\":");
        emit_i64(b, c->ret_i, c->ret_k);
    } else if (c->ret_kind == 2) {
        buf_puts(b, ",\"r\":");
        emit_f64(b, c->ret_f);
    } else if (c->ret_kind == 3) {
        buf_puts(b, ",\"r\":{\"k\":\"void\"}");
    }
    if (c->has_err) {
        buf_puts(b, ",\"e\":");
        buf_u64(b, c->err);
    }
    buf_puts(b, "}\n");

    if (b->oom)
        note_lim(c->sym, "record dropped: trace buffer allocation failed");
    else
        (void)sink_line(b->p, b->len);

    ts = c->ts;
    if (ts && ts->depth > 0)
        ts->depth--;            /* the stack slot is overwritten by the next enter */
    if (c->heap) {
        buf_free(b);
        tr_heap_free(c);
    } else {
        b->len = 0;
    }
    InterlockedDecrement(&g_inflight);
}
