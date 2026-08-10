/* shimforge selftest -- the consumer.
 *
 * Only knows the v1 ABI. Runs a realistic sequence (two live handles, error
 * paths, progress callbacks, a size-negotiated readback) and writes an output
 * file, so `runner.py` has an exit code, a stdout and a file hash to compare.
 *
 * Everything printed is implementation independent on purpose: no pointers,
 * no handle values, no timings. That makes "run/old stdout == run/ok stdout"
 * a meaningful assertion, and any stdout difference from a shim a real
 * behavioural difference rather than an address reshuffle.
 *
 * Usage: app.exe [outfile]
 */

/* The UCRT headers deprecate fopen in favour of fopen_s. The self-test wants
 * plain C89-shaped code that a reviewer can read, and -Werror would otherwise
 * turn that style choice into a build failure. */
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define OLD_OK           0
#define OLD_E_TOOSMALL  (-4)

typedef struct OLD_BUF {
    unsigned int   size;
    unsigned char *data;
    unsigned int   len;
} OLD_BUF;

typedef struct OLD_STAT {
    unsigned int       size;
    unsigned int       nproc;
    unsigned int       nbytes;
    unsigned int       checksum;
    unsigned long long ticks;
} OLD_STAT;

typedef int (__stdcall *OLD_PROGRESS)(void *h, int pct);
typedef unsigned int (__stdcall *PFN_VERSION)(void);

__declspec(dllimport) int __stdcall Init(const char *tag, void *reserved);
__declspec(dllimport) void * __stdcall Open(const char *name, unsigned int mode);
__declspec(dllimport) int __stdcall SetCallback(void *h, OLD_PROGRESS cb);
__declspec(dllimport) int __stdcall Process(void *h, OLD_BUF *buf, int flags);
__declspec(dllimport) int __stdcall Read(void *h, unsigned char *out,
                                         unsigned int cap,
                                         unsigned int *out_len);
__declspec(dllimport) int __stdcall GetStats(void *h, OLD_STAT *st);
__declspec(dllimport) int __stdcall Close(void *h);

/* An opaque host object handed to Init. A production contract could not infer
 * its size from the ABI, but this closed self-test owns the call site and
 * declares the exact 8-byte scenario extent. Leaving it unknown would make a
 * full-coverage PASS impossible -- correctly -- under fail-closed checking. */
static struct app_config {
    unsigned int magic;
    unsigned int reserved;
} g_config = { 0x5FA17E57u, 0u };

#define LABEL_MAX 4
static struct {
    void       *h;
    const char *label;
} g_labels[LABEL_MAX];
static int g_label_n;

static void bind_label(void *h, const char *label)
{
    if (g_label_n < LABEL_MAX) {
        g_labels[g_label_n].h = h;
        g_labels[g_label_n].label = label;
        g_label_n++;
    }
}

static const char *label_of(void *h)
{
    int i;

    for (i = 0; i < g_label_n; i++) {
        if (g_labels[i].h == h)
            return g_labels[i].label;
    }
    return "?";
}

static unsigned int fold32(const unsigned char *p, unsigned int n)
{
    unsigned int h = 2166136261u;
    unsigned int i;

    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static void print_hex(const char *label, const unsigned char *p, unsigned int n)
{
    unsigned int i;

    printf("hex %s", label);
    for (i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

static int __stdcall on_progress(void *h, int pct)
{
    printf("[cb] %s pct=%d\n", label_of(h), pct);
    return 0;
}

/* Process + read back + append to the output file: the shape a real consumer
 * uses, and the shape that makes a shifted payload visible. */
static void do_round(void *h, const char *text, int flags, FILE *fp)
{
    unsigned char work[256];
    unsigned char rb[256];
    OLD_BUF b;
    unsigned int n = (unsigned int)strlen(text);
    unsigned int got = 0;
    const char *label = label_of(h);
    int rc;

    memset(work, 0, sizeof(work));
    memcpy(work, text, n);
    memset(&b, 0, sizeof(b));      /* zero the padding too: keeps the recorded
                                    * struct bytes deterministic run to run */
    b.size = (unsigned int)sizeof(OLD_BUF);
    b.data = work;
    b.len = n;

    rc = Process(h, &b, flags);
    printf("process %s rc=%d len=%u\n", label, rc, b.len);

    memset(rb, 0, sizeof(rb));
    rc = Read(h, rb, (unsigned int)sizeof(rb), &got);
    printf("read %s rc=%d n=%u fold=%08x\n", label, rc, got, fold32(rb, got));
    print_hex(label, rb, got < 16u ? got : 16u);
    if (rc == OLD_OK && got > 0u && fp != NULL)
        fwrite(rb, 1, got, fp);
}

int main(int argc, char **argv)
{
    const char *outpath = (argc > 1) ? argv[1] : "out.bin";
    HMODULE mod;
    PFN_VERSION pfn_version;
    OLD_BUF alias;
    OLD_STAT st;
    unsigned char rb[256];
    unsigned int got = 0;
    void *h1;
    void *h2;
    void *hbad;
    FILE *fp;
    int rc;

    printf("== shimforge selftest app ==\n");

    /* Version is exported NONAME at ordinal 8; it can only be reached the way
     * a real consumer would reach it. */
    mod = GetModuleHandleA("oldlib.dll");
    if (mod == NULL) {
        printf("fatal: oldlib.dll not loaded\n");
        return 2;
    }
    pfn_version = (PFN_VERSION)(void *)GetProcAddress(mod, MAKEINTRESOURCEA(8));
    if (pfn_version == NULL) {
        printf("fatal: ordinal 8 missing\n");
        return 2;
    }
    printf("version=%08x\n", pfn_version());
    printf("version-again=%08x,%08x\n", pfn_version(), pfn_version());

    printf("init null rc=%d\n", Init(NULL, NULL));
    printf("init empty rc=%d\n", Init("", NULL));
    rc = Init("selftest", &g_config);
    printf("init rc=%d\n", rc);
    if (rc != OLD_OK)
        return 2;

    SetLastError(ERROR_SUCCESS);
    hbad = Open("", 0u);
    printf("open bad null=%d err=%lu\n", hbad == NULL ? 1 : 0,
           (unsigned long)GetLastError());

    h1 = Open("alpha", 1u);
    h2 = Open("beta", 2u);
    if (h1 == NULL || h2 == NULL) {
        printf("fatal: open failed\n");
        return 2;
    }
    bind_label(h1, "alpha");
    bind_label(h2, "beta");
    printf("open alpha ok=%d\n", 1);
    printf("open beta ok=%d\n", 1);

    printf("setcb alpha rc=%d\n", SetCallback(h1, on_progress));
    printf("setcb beta rc=%d\n", SetCallback(h2, on_progress));
    printf("setcb beta-off rc=%d\n", SetCallback(h2, NULL));
    printf("setcb beta-on rc=%d\n", SetCallback(h2, on_progress));

    fp = fopen(outpath, "wb");
    if (fp == NULL) {
        printf("fatal: cannot write %s\n", outpath);
        return 2;
    }

    do_round(h1, "shimforge selftest payload one 0123456789ab", 0x11, fp);
    do_round(h1, "second round", 0, fp);
    do_round(h2, "beta channel payload 42", 0x22, fp);

    /* Size negotiation: too small first, then the real read. */
    memset(rb, 0, sizeof(rb));
    rc = Read(h2, rb, 8u, &got);
    printf("read beta small rc=%d need=%u\n", rc, got);
    if (rc == OLD_E_TOOSMALL) {
        memset(rb, 0, sizeof(rb));
        rc = Read(h2, rb, (unsigned int)sizeof(rb), &got);
        printf("read beta retry rc=%d n=%u fold=%08x\n", rc, got,
               fold32(rb, got));
    }

    memset(&st, 0, sizeof(st));
    st.size = (unsigned int)sizeof(st);
    rc = GetStats(h1, &st);
    printf("stats alpha rc=%d nproc=%u nbytes=%u crc=%08x\n", rc, st.nproc,
           st.nbytes, st.checksum);

    memset(&st, 0, sizeof(st));
    st.size = (unsigned int)sizeof(st);
    rc = GetStats(h2, &st);
    printf("stats beta rc=%d nproc=%u nbytes=%u crc=%08x\n", rc, st.nproc,
           st.nbytes, st.checksum);

    printf("stats null rc=%d\n", GetStats(h1, NULL));

    /* Feed the readback buffer straight back in as the payload. The same
     * address now reaches the library twice in two different shapes: as a
     * top-level argument (Read's `out`, above) and embedded in a struct
     * (OLD_BUF.data). A normalizer that symbolizes both through one table
     * renders them as one token; one that only symbolizes top-level pointers
     * cannot relate them at all. Only the return code is printed, so this
     * stays implementation independent like everything else here. */
    memset(&alias, 0, sizeof(alias));
    alias.size = (unsigned int)sizeof(OLD_BUF);
    alias.data = rb;
    alias.len = 8u;
    printf("process alias rc=%d\n", Process(h2, &alias, 0x22));

    printf("close alpha rc=%d\n", Close(h1));
    printf("close beta rc=%d\n", Close(h2));
    printf("close null rc=%d\n", Close(NULL));

    fclose(fp);
    /* Keep the acceptance scenario above the oracle's minimum timing window;
     * otherwise process-startup jitter, not recorder overhead, dominates the
     * noninterference ratio and a PASS would not be meaningful. */
    Sleep(100);
    printf("wrote %s\n", outpath);
    printf("== done ==\n");
    return 0;
}
