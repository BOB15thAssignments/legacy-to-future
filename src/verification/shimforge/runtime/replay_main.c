/* shimforge deterministic replay driver -- the fixed engine.
 *
 * Re-feeds one recorded call sequence to a shim DLL with no application in
 * the loop, and emits its own trace through tr_record.h so the differ works
 * on the result unchanged. gen_replay.py emits "replay_gen.h" with the
 * recorded data and the typed thunks for one contract; it is included below,
 * so engine and generated code form a single translation unit.
 *
 *   clang -O1 -Wall -Wextra -o replay.exe replay_main.c tr_record.c \
 *         -I <gen dir> -I <runtime dir>
 *   replay.exe [shim.dll] [out.jsonl] [replay_blob.bin]
 *
 * Single threaded on purpose. A trace records one arbitrary interleaving of
 * many legal ones, so replaying several threads would compare a schedule,
 * not behaviour; the generator hands us one thread's subsequence and reports
 * the rest as dropped. Multi-thread replay is out of scope.
 *
 * A mismatch (unexpected callback, wrong callback argument, missing export)
 * is recorded as a note and the run continues. Stopping at the first one
 * would hide everything downstream from the differ, which is exactly the
 * picture a human needs to fix the shim.
 */

#define _CRT_SECURE_NO_WARNINGS 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tr_record.h"

/* Bytes appended after every replay buffer, poisoned and checked after the
 * call. The recorded extent is what the original DLL touched; a shim that
 * writes past it is a real finding, and without the pad it would corrupt the
 * heap before we could report it. */
#define RP_GUARD 64
#define RP_POISON 0xCD
#define RP_MAX_ARGS 32

typedef union rp_val {
    long long i;
    double f;
    void *p;
} rp_val;

/* gen_replay.py emits these names symbolically, so a generator/engine
 * disagreement is a compile error rather than a mis-decoded table. */
enum {
    RP_K_VOID = 0, RP_K_BOOL, RP_K_I8, RP_K_U8, RP_K_I16, RP_K_U16,
    RP_K_I32, RP_K_U32, RP_K_I64, RP_K_U64, RP_K_F32, RP_K_F64,
    RP_K_PTR, RP_K_STR, RP_K_WSTR, RP_K_HANDLE, RP_K_FNPTR, RP_K_BLOB
};

enum { RP_D_IN = 0, RP_D_OUT, RP_D_INOUT };

enum {
    RP_P_SCALAR = 0,  /* by value, integer                                */
    RP_P_FLOAT,       /* by value, floating point                         */
    RP_P_PTRVAL,      /* by value, opaque token (slot substituted)        */
    RP_P_BUFFER,      /* pointer to a byte buffer the driver owns         */
    RP_P_REF,         /* pointer to a scalar cell the callee writes       */
    RP_P_CB           /* pointer to a generated callback trampoline       */
};

typedef struct rp_arg {
    const char *name;
    const char *kindname;   /* kind string handed to tr_*                 */
    int kind;               /* RP_K_*                                     */
    int dir;                /* RP_D_*                                     */
    int pass;               /* RP_P_*                                     */
    int is_null;            /* the recorded pointer was NULL              */
    int slot;               /* >=0: substitute this slot's live value     */
    int creates;            /* >=0: bind this slot from the live value    */
    int cb;                 /* >=0: index into RP_CBS                     */
    long long ival;
    double fval;
    long long in_len;       /* recorded input bytes, <0 = none            */
    long long out_len;      /* recorded output bytes, <0 = unknown        */
    unsigned in_off;        /* offset of the input bytes in the blob      */
    int in_captured;
} rp_arg;

typedef struct rp_rec {
    int seq, tid, symi, is_cb, parent;
    const char *sym;
    const rp_arg *args;
    int nargs;
    int kid0, nkids;        /* window into RP_KIDS                        */
    int has_ret, ret_kind, ret_slot;
    const char *ret_kindname;
    long long ret_i;
    double ret_f;
    int has_lasterr;
    unsigned long lasterr;
    const char *skip;       /* non-NULL: do not call, emit this note      */
} rp_rec;

typedef void (*rp_invoke_fn)(void *fn, rp_val *a, rp_val *r);

typedef struct rp_sym {
    const char *name;
    int ordinal, noname;
    rp_invoke_fn invoke;
    void *fn;
    int missing;
} rp_sym;

typedef struct rp_cb {
    const char *name;
    void *fn;
    const rp_arg *proto;    /* names and kinds, independent of any record */
    int nargs;
    int ret_kind;
    const char *ret_kindname;
} rp_cb;

static void rp_callback_hit(int cb_index, rp_val *a, int nargs, rp_val *ret);

#include "replay_gen.h"

/* ------------------------------------------------------------------ state */

static const unsigned char *rp_blob;
static size_t rp_blob_len;
static unsigned char *rp_blob_owned;

/* +1 so a contract with no symbolic objects still declares a legal array. */
static long long rp_slot_val[RP_NSLOTS + 1];
static unsigned char rp_slot_bound[RP_NSLOTS + 1];

static const rp_rec *rp_cur;    /* record whose call is in flight */
static int rp_kid_cursor;
static const char *rp_dll_name = RP_MODULE;
static char *rp_dll_owned;

static long rp_n_called, rp_n_skipped, rp_n_cb, rp_n_mismatch;

static void rp_notef(const char *sym, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void rp_notef(const char *sym, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    tr_note(sym, buf);
}

/* ------------------------------------------------------------------- blob */

static int rp_blob_init(const char *path)
{
#if RP_BLOB_EXTERNAL
    FILE *fh = fopen(path, "rb");
    long n;
    if (!fh) {
        fprintf(stderr, "replay: cannot open blob '%s'\n", path);
        return 0;
    }
    if (fseek(fh, 0, SEEK_END) != 0) {
        fprintf(stderr, "replay: cannot seek blob '%s'\n", path);
        fclose(fh);
        return 0;
    }
    n = ftell(fh);
    if (n < 0 || fseek(fh, 0, SEEK_SET) != 0) {
        fprintf(stderr, "replay: cannot size blob '%s'\n", path);
        fclose(fh);
        return 0;
    }
    if ((size_t)n != (size_t)RP_BLOB_SIZE) {
        fprintf(stderr, "replay: blob is %ld bytes, expected %d\n",
                n, RP_BLOB_SIZE);
        fclose(fh);
        return 0;
    }
    rp_blob_owned = (unsigned char *)malloc((size_t)n + 1);
    if (!rp_blob_owned) {
        fprintf(stderr, "replay: out of memory reading blob\n");
        fclose(fh);
        return 0;
    }
    rp_blob_len = fread(rp_blob_owned, 1, (size_t)n, fh);
    fclose(fh);
    rp_blob = rp_blob_owned;
    if (rp_blob_len != (size_t)n) {
        fprintf(stderr, "replay: short read from blob '%s'\n", path);
        return 0;
    }
#else
    (void)path;
    rp_blob = RP_BLOB_DATA;
    rp_blob_len = (size_t)RP_BLOB_SIZE;
#endif
    return 1;
}

static const unsigned char *rp_blob_at(unsigned off, long long len,
                                       const char *what)
{
    if (len <= 0)
        return NULL;
    if ((unsigned long long)len > (unsigned long long)SIZE_MAX ||
        (size_t)off > rp_blob_len || (size_t)len > rp_blob_len - (size_t)off) {
        rp_notef("", "blob range %u+%lld out of bounds for %s",
                 off, len, what ? what : "?");
        rp_n_mismatch++;
        return NULL;
    }
    return rp_blob + off;
}

/* ------------------------------------------------------------- scalar i/o */

static long long rp_read_scalar(int kind, const void *p)
{
    /* memcpy throughout: the cell is a union, and a shim may leave it
     * misaligned relative to the wider type we are reading back. */
    switch (kind) {
    case RP_K_I8:  { signed char v;        memcpy(&v, p, 1); return v; }
    case RP_K_U8:  { unsigned char v;      memcpy(&v, p, 1); return v; }
    case RP_K_I16: { short v;              memcpy(&v, p, 2); return v; }
    case RP_K_U16: { unsigned short v;     memcpy(&v, p, 2); return v; }
    case RP_K_BOOL:
    case RP_K_I32: { int v;                memcpy(&v, p, 4); return v; }
    case RP_K_U32: { unsigned int v;       memcpy(&v, p, 4); return v; }
    case RP_K_I64: { long long v;          memcpy(&v, p, 8); return v; }
    case RP_K_U64: { unsigned long long v; memcpy(&v, p, 8);
                     return (long long)v; }
    case RP_K_F32: { float v;              memcpy(&v, p, 4);
                     return (long long)v; }
    case RP_K_F64: { double v;             memcpy(&v, p, 8);
                     return (long long)v; }
    default:       { void *v;              memcpy(&v, p, sizeof v);
                     return (long long)(intptr_t)v; }
    }
}

static double rp_read_double(int kind, const void *p)
{
    if (kind == RP_K_F32) { float v;  memcpy(&v, p, 4); return (double)v; }
    if (kind == RP_K_F64) { double v; memcpy(&v, p, 8); return v; }
    return (double)rp_read_scalar(kind, p);
}

static long long rp_live_of(const rp_arg *a)
{
    if (a->slot >= 0 && a->slot < RP_NSLOTS && rp_slot_bound[a->slot])
        return rp_slot_val[a->slot];
    return a->ival;
}

static void rp_slot_set(int slot, long long v, const char *sym,
                        const char *what)
{
    if (slot < 0 || slot >= RP_NSLOTS)
        return;
    if (!v) {
        /* The recording only mints a slot for a non-NULL object, so NULL here
         * means the shim failed to create one. Leaving the slot unbound makes
         * every dependent record skip, which is better than calling the shim
         * with a handle it never handed out. */
        rp_notef(sym, "%s produced NULL where the recording created an "
                 "object; dependent calls will be skipped", what);
        rp_n_mismatch++;
        return;
    }
    rp_slot_val[slot] = v;
    rp_slot_bound[slot] = 1;
}

/* --------------------------------------------------------------- argument */

typedef struct rp_store {
    unsigned char *buf;     /* arena slice, includes the guard pad */
    size_t len;             /* usable bytes, guard excluded */
    rp_val cell;            /* by-ref scalar storage handed to the callee */
} rp_store;

/* Buffer arguments come out of one arena that is reset per call, NOT out of
 * malloc. The address of a buffer reaches the trace through tr_in_ptr /
 * tr_out_ptr, and normalize.py turns pointer values into @ext tokens numbered
 * in first-sight order. With malloc, whether a later call happens to get an
 * address an earlier one already used is an allocator decision that varies
 * between runs, so the token numbering varied too and replaying one trace
 * against one DLL twice produced divergences -- exactly what the oracle's
 * determinism check forbids. Fixed offsets inside one block make the sequence
 * of distinct addresses identical in every run; the base differs, which does
 * not matter because only the tokens are compared. */
static unsigned char *rp_arena;
static size_t rp_arena_len, rp_arena_used;

static size_t rp_slice_size(const rp_arg *a)
{
    long long want;

    if (a->pass != RP_P_BUFFER || a->is_null)
        return 0;
    want = a->in_len > a->out_len ? a->in_len : a->out_len;
    if (want < 1)
        want = 1;
    /* Rounded up so every slice starts aligned: a callee is entitled to read
     * the bytes as the struct the contract says they are. */
    return (((size_t)want + RP_GUARD) + 15u) & ~(size_t)15u;
}

static void rp_arena_init(void)
{
    size_t need = 0;
    int i, j;

    for (i = 0; i < RP_NRECS; i++) {
        const rp_rec *r = &RP_RECS[i];
        size_t sum = 0;
        if (r->is_cb)
            continue;
        if (r->skip)
            continue;
        for (j = 0; j < r->nargs; j++)
            sum += rp_slice_size(&r->args[j]);
        if (sum > need)
            need = sum;
    }
    if (!need)
        return;
    rp_arena = (unsigned char *)malloc(need);
    if (!rp_arena) {
        fprintf(stderr, "replay: cannot allocate a %zu byte argument arena\n",
                need);
        exit(2);
    }
    rp_arena_len = need;
}

static void rp_prepare(const rp_arg *a, rp_store *st, rp_val *v)
{
    long long want;
    size_t slice;

    switch (a->pass) {
    case RP_P_CB:
        v->p = (a->cb >= 0 && a->cb < RP_NCB) ? RP_CBS[a->cb].fn : NULL;
        break;

    case RP_P_BUFFER:
        if (a->is_null) {
            v->p = NULL;
            break;
        }
        want = a->in_len > a->out_len ? a->in_len : a->out_len;
        if (want < 1)
            want = 1;
        st->len = (size_t)want;
        slice = rp_slice_size(a);
        if (slice > rp_arena_len - rp_arena_used) {
            v->p = NULL;
            st->buf = NULL;
            rp_notef("", "argument arena exhausted for '%s'", a->name);
            rp_n_mismatch++;
            break;
        }
        st->buf = rp_arena + rp_arena_used;
        rp_arena_used += slice;
        /* Poison first: an out arg an adapter forgets to fill then shows up
         * as 0xCD in the diff instead of as plausible looking zeroes. */
        memset(st->buf, RP_POISON, st->len + RP_GUARD);
        if (a->in_captured) {
            const unsigned char *src = rp_blob_at(a->in_off, a->in_len,
                                                  a->name);
            if (src)
                memcpy(st->buf, src, (size_t)a->in_len);
        }
        v->p = st->buf;
        break;

    case RP_P_REF:
        if (a->dir != RP_D_INOUT) {
            memset(&st->cell, RP_POISON, sizeof st->cell);
        } else if (a->kind == RP_K_F64) {
            st->cell.f = a->fval;
        } else if (a->kind == RP_K_F32) {
            /* The cell is a union: a float has to land in its own width or
             * the callee reads the low half of a double. */
            float f32 = (float)a->fval;
            memset(&st->cell, 0, sizeof st->cell);
            memcpy(&st->cell, &f32, sizeof f32);
        } else {
            st->cell.i = rp_live_of(a);
        }
        v->p = &st->cell;
        break;

    case RP_P_PTRVAL:
        v->p = (void *)(intptr_t)rp_live_of(a);
        break;

    case RP_P_FLOAT:
        v->f = a->fval;
        break;

    default:
        /* rp_live_of, not a->ival: an integer-typed argument the contract
         * declares symbolize/creates/releases carries an object identity and
         * gets the same slot substitution a handle does. Without a slot it
         * returns a->ival, so a plain scalar is unaffected. */
        v->i = rp_live_of(a);
        break;
    }
}

static void rp_emit_in(tr_call *c, const rp_arg *a, rp_store *st, rp_val *v)
{
    if (a->dir == RP_D_OUT)
        return;
    switch (a->pass) {
    case RP_P_CB:
    case RP_P_PTRVAL:
        tr_in_i64(c, a->name, (long long)(intptr_t)v->p, a->kindname);
        break;
    case RP_P_BUFFER:
        if (a->kind == RP_K_STR)
            tr_in_str(c, a->name, (const char *)st->buf);
        else if (a->kind == RP_K_WSTR)
            tr_in_wstr(c, a->name, (const unsigned short *)st->buf);
        else
            tr_in_ptr(c, a->name, st->buf, a->is_null ? 0 : a->in_len);
        break;
    case RP_P_REF:
        if (a->kind == RP_K_F32 || a->kind == RP_K_F64)
            tr_in_f64(c, a->name, rp_read_double(a->kind, &st->cell));
        else
            tr_in_i64(c, a->name, st->cell.i, a->kindname);
        break;
    case RP_P_FLOAT:
        tr_in_f64(c, a->name, v->f);
        break;
    default:
        tr_in_i64(c, a->name, v->i, a->kindname);
        break;
    }
}

static void rp_emit_out(tr_call *c, const rp_arg *a, rp_store *st)
{
    if (a->dir == RP_D_IN)
        return;
    if (a->pass == RP_P_BUFFER) {
        long long n = a->out_len;
        if (a->kind == RP_K_STR) {
            tr_out_str(c, a->name, (const char *)st->buf);
            return;
        }
        if (a->kind == RP_K_WSTR) {
            tr_out_wstr(c, a->name, (const unsigned short *)st->buf);
            return;
        }
        if (a->is_null || !st->buf) {
            tr_out_ptr(c, a->name, NULL, 0);
            return;
        }
        /* Never report more than we allocated: out_len is the extent the
         * original DLL wrote, and the shim's buffer is only that big. */
        if (n < 0 || (size_t)n > st->len)
            n = (long long)st->len;
        tr_out_ptr(c, a->name, st->buf, n);
        return;
    }
    if (a->pass == RP_P_REF) {
        if (a->kind == RP_K_F32 || a->kind == RP_K_F64) {
            tr_out_f64(c, a->name, rp_read_double(a->kind, &st->cell));
            return;
        }
        tr_out_i64(c, a->name, rp_read_scalar(a->kind, &st->cell),
                   a->kindname);
    }
}

static void rp_check_guard(const rp_arg *a, const rp_store *st,
                           const char *sym)
{
    size_t i;
    if (!st->buf)
        return;
    for (i = 0; i < (size_t)RP_GUARD; i++) {
        if (st->buf[st->len + i] != RP_POISON) {
            rp_notef(sym, "'%s': shim modified guard byte +%zu past the "
                     "recorded extent of %zu", a->name, i, st->len);
            rp_n_mismatch++;
            return;
        }
    }
}

static void rp_bind(const rp_arg *a, const rp_store *st, const char *sym)
{
    if (a->creates < 0)
        return;
    if (a->pass == RP_P_BUFFER) {
        void *v = NULL;
        if (st->buf && st->len >= sizeof v)
            memcpy(&v, st->buf, sizeof v);
        rp_slot_set(a->creates, (long long)(intptr_t)v, sym, a->name);
        return;
    }
    if (a->pass == RP_P_REF) {
        rp_slot_set(a->creates, rp_read_scalar(a->kind, &st->cell), sym,
                    a->name);
    }
}

/* -------------------------------------------------------------- callbacks */

static void rp_compare_cb_arg(const char *cbname, const rp_arg *e,
                              const rp_val *live)
{
    long long want;

    switch (e->pass) {
    case RP_P_FLOAT:
        if (live->f != e->fval) {
            rp_notef(cbname, "arg '%s': recorded %.17g, shim passed %.17g",
                     e->name, e->fval, live->f);
            rp_n_mismatch++;
        }
        return;

    case RP_P_PTRVAL:
    case RP_P_CB:
        want = rp_live_of(e);
        if ((long long)(intptr_t)live->p != want) {
            rp_notef(cbname, "arg '%s': expected %#llx, shim passed %#llx",
                     e->name, (unsigned long long)want,
                     (unsigned long long)(intptr_t)live->p);
            rp_n_mismatch++;
        }
        return;

    case RP_P_BUFFER: {
        const unsigned char *want_b;
        if (e->is_null) {
            if (live->p) {
                rp_notef(cbname, "arg '%s': recorded NULL, shim passed a "
                         "pointer", e->name);
                rp_n_mismatch++;
            }
            return;
        }
        if (!live->p) {
            rp_notef(cbname, "arg '%s': recorded a buffer, shim passed NULL",
                     e->name);
            rp_n_mismatch++;
            return;
        }
        want_b = rp_blob_at(e->in_off, e->in_len, e->name);
        if (want_b && memcmp(want_b, live->p, (size_t)e->in_len) != 0) {
            const unsigned char *got = (const unsigned char *)live->p;
            long long i;
            for (i = 0; i < e->in_len && want_b[i] == got[i]; i++)
                ;
            rp_notef(cbname, "arg '%s': content differs at byte %lld "
                     "(recorded %02x, shim %02x)", e->name, i,
                     want_b[i], got[i]);
            rp_n_mismatch++;
        }
        return;
    }

    default:
        /* rp_live_of for the same reason rp_prepare uses it: an integer that
         * carries an object identity must be compared against the live value,
         * not the address the recording happened to see. */
        want = rp_live_of(e);
        if (live->i != want) {
            rp_notef(cbname, "arg '%s': expected %lld, shim passed %lld",
                     e->name, want, live->i);
            rp_n_mismatch++;
        }
        return;
    }
}

static void rp_callback_hit(int cb_index, rp_val *a, int nargs, rp_val *ret)
{
    const rp_cb *cb = (cb_index >= 0 && cb_index < RP_NCB)
                      ? &RP_CBS[cb_index] : NULL;
    const char *name = cb ? cb->name : "?";
    const rp_rec *exp = NULL;
    tr_call *c;
    int i;

    ret->i = 0;
    ret->f = 0.0;
    rp_n_cb++;

    if (rp_cur) {
        int end = rp_cur->kid0 + rp_cur->nkids;
        int j;
        for (j = rp_kid_cursor; j < end; j++) {
            const rp_rec *k = &RP_RECS[RP_KIDS[j]];
            if (strcmp(k->sym, name) != 0)
                continue;
            if (j != rp_kid_cursor) {
                rp_notef(name, "invoked out of order: %d recorded callback(s) "
                         "skipped inside %s", j - rp_kid_cursor,
                         rp_cur->sym);
                rp_n_mismatch++;
            }
            exp = k;
            rp_kid_cursor = j + 1;
            break;
        }
    }

    c = tr_enter(name, 1);
    for (i = 0; i < nargs; i++) {
        const rp_arg *pa = (cb && i < cb->nargs) ? &cb->proto[i] : NULL;
        if (!pa) {
            tr_in_i64(c, "?", a[i].i, "i64");
            continue;
        }
        switch (pa->pass) {
        case RP_P_FLOAT:
            tr_in_f64(c, pa->name, a[i].f);
            break;
        case RP_P_BUFFER:
            if (pa->kind == RP_K_STR)
                tr_in_str(c, pa->name, (const char *)a[i].p);
            else if (pa->kind == RP_K_WSTR)
                tr_in_wstr(c, pa->name, (const unsigned short *)a[i].p);
            else
                tr_in_ptr(c, pa->name, a[i].p,
                          exp && i < exp->nargs ? exp->args[i].in_len : -1);
            break;
        case RP_P_PTRVAL:
        case RP_P_CB:
        case RP_P_REF:
            tr_in_i64(c, pa->name, (long long)(intptr_t)a[i].p,
                      pa->kindname);
            break;
        default:
            tr_in_i64(c, pa->name, a[i].i, pa->kindname);
            break;
        }
    }

    if (exp) {
        int n = exp->nargs < nargs ? exp->nargs : nargs;
        if (exp->nargs != nargs) {
            rp_notef(name, "arity mismatch: recorded %d args, trampoline saw "
                     "%d", exp->nargs, nargs);
            rp_n_mismatch++;
        }
        for (i = 0; i < n; i++)
            rp_compare_cb_arg(name, &exp->args[i], &a[i]);
        /* Deterministic replay: hand back exactly what the application
         * answered, so the shim follows the recorded path. */
        ret->i = exp->ret_i;
        ret->f = exp->ret_f;
    } else {
        rp_notef(name, "unexpected callback: nothing matching was recorded "
                 "inside %s", rp_cur ? rp_cur->sym : "(no call in flight)");
        rp_n_mismatch++;
    }

    if (cb && cb->ret_kind == RP_K_VOID)
        tr_ret_void(c);
    else if (cb && (cb->ret_kind == RP_K_F32 || cb->ret_kind == RP_K_F64))
        tr_ret_f64(c, ret->f);
    else
        tr_ret_i64(c, ret->i, cb ? cb->ret_kindname : "i32");
    tr_leave(c);
}

/* ------------------------------------------------------------------- call */

static HMODULE rp_mod;

static void *rp_resolve(rp_sym *s)
{
    FARPROC p;
    if (s->fn || s->missing)
        return s->fn;
    p = s->noname ? GetProcAddress(rp_mod, MAKEINTRESOURCEA(s->ordinal))
                  : GetProcAddress(rp_mod, s->name);
    if (!p) {
        s->missing = 1;
        return NULL;
    }
    s->fn = (void *)(intptr_t)p;
    return s->fn;
}

/* An arg bound to a slot no completed call has filled means the object it
 * names does not exist in this run -- the creating call was skipped or the
 * shim failed it. Passing the recorded address through would hand the shim a
 * pointer from another process, so the record is dropped instead. A slot of
 * -1 is different: that value came from outside the recording and the raw
 * value is all anyone ever had. */
static const rp_arg *rp_unbound_dep(const rp_rec *rec)
{
    int i;
    for (i = 0; i < rec->nargs; i++) {
        const rp_arg *a = &rec->args[i];
        if (a->slot >= 0 && a->slot < RP_NSLOTS && !rp_slot_bound[a->slot])
            return a;
    }
    return NULL;
}

static void rp_do_call(const rp_rec *rec)
{
    rp_store st[RP_MAX_ARGS];
    rp_val av[RP_MAX_ARGS];
    const rp_arg *dep;
    rp_val rv;
    rp_sym *sym;
    tr_call *c;
    DWORD le;
    int i, leftover;

    if (rec->skip) {
        rp_notef(rec->sym, "record %d not replayed: %s", rec->seq, rec->skip);
        rp_n_skipped++;
        return;
    }
    if (rec->symi < 0 || rec->symi >= RP_NSYMS) {
        rp_notef(rec->sym, "record %d has no generated thunk", rec->seq);
        rp_n_skipped++;
        return;
    }
    sym = &RP_SYMS[rec->symi];
    if (!rp_resolve(sym)) {
        rp_notef(rec->sym, "not exported by %s", rp_dll_name);
        rp_n_skipped++;
        return;
    }
    dep = rp_unbound_dep(rec);
    if (dep) {
        rp_notef(rec->sym, "record %d not replayed: '%s' names slot %d, which "
                 "no completed call bound", rec->seq, dep->name, dep->slot);
        rp_n_skipped++;
        return;
    }

    memset(st, 0, sizeof st);
    memset(av, 0, sizeof av);
    rp_arena_used = 0;          /* sized for the largest single call */
    for (i = 0; i < rec->nargs; i++)
        rp_prepare(&rec->args[i], &st[i], &av[i]);

    c = tr_enter(rec->sym, 0);
    for (i = 0; i < rec->nargs; i++)
        rp_emit_in(c, &rec->args[i], &st[i], &av[i]);

    rp_cur = rec;
    rp_kid_cursor = rec->kid0;
    rv.i = 0;
    SetLastError(0);            /* a stale error must not look like this call's */
    sym->invoke(sym->fn, av, &rv);
    le = GetLastError();        /* before anything else can clobber it */
    rp_cur = NULL;

    for (i = 0; i < rec->nargs; i++)
        rp_emit_out(c, &rec->args[i], &st[i]);
    if (!rec->has_ret)
        tr_ret_void(c);
    else if (rec->ret_kind == RP_K_F32 || rec->ret_kind == RP_K_F64)
        tr_ret_f64(c, rv.f);
    else
        tr_ret_i64(c, rv.i, rec->ret_kindname);
    if (rec->has_lasterr)
        tr_lasterr(c, le);
    tr_leave(c);

    for (i = 0; i < rec->nargs; i++) {
        rp_check_guard(&rec->args[i], &st[i], rec->sym);
        rp_bind(&rec->args[i], &st[i], rec->sym);
    }
    if (rec->ret_slot >= 0)
        rp_slot_set(rec->ret_slot, rv.i, rec->sym, "return value");

    leftover = rec->kid0 + rec->nkids - rp_kid_cursor;
    if (leftover > 0) {
        rp_notef(rec->sym, "%d recorded callback(s) were never invoked",
                 leftover);
        rp_n_mismatch++;
    }

    rp_n_called++;
}

/* ------------------------------------------------------------------- main */

static const char *rp_env(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

/* Resolve even a caller-supplied bare name to one exact absolute path before
 * loading it. LoadLibrary's ambient search order is not acceptable evidence:
 * it can silently replay a different DLL from PATH or the current process. */
static HMODULE rp_load_module(const char *name)
{
    DWORD cap, n;

    cap = GetFullPathNameA(name, 0, NULL, NULL);
    if (!cap)
        return NULL;
    rp_dll_owned = (char *)malloc((size_t)cap);
    if (!rp_dll_owned)
        return NULL;
    n = GetFullPathNameA(name, cap, rp_dll_owned, NULL);
    if (!n || n >= cap) {
        free(rp_dll_owned);
        rp_dll_owned = NULL;
        return NULL;
    }
    rp_dll_name = rp_dll_owned;
    return LoadLibraryExA(rp_dll_name, NULL,
                          LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                          LOAD_LIBRARY_SEARCH_SYSTEM32);
}

int main(int argc, char **argv)
{
    const char *out;
    const char *blob;
    int i, incomplete, rc = 0;

    /* Only the generated trampolines call it, and a contract without
     * callbacks generates none. */
    (void)rp_callback_hit;

    rp_dll_name = (argc > 1) ? argv[1] : RP_MODULE;
    out = (argc > 2) ? argv[2]
                     : rp_env("SHIMFORGE_REPLAY_TRACE", "replay.trace.jsonl");
    blob = (argc > 3) ? argv[3] : RP_BLOB_FILE;

    if (!rp_blob_init(blob))
        return 2;
    rp_arena_init();

    rp_mod = rp_load_module(rp_dll_name);
    if (!rp_mod) {
        fprintf(stderr, "replay: safe load of \"%s\" failed, err=%lu\n",
                rp_dll_name, (unsigned long)GetLastError());
        rc = 1;
        goto cleanup;
    }

    tr_init(out, RP_MODULE, RP_ARCH, RP_LABEL, RP_CONTRACT_HASH);
    if (!tr_enabled()) {
        fprintf(stderr, "replay: tr_record is disabled, no trace will be "
                        "written to '%s'\n", out);
        rc = 3;
        goto cleanup;
    }
    if (RP_DROPPED_THREADS)
        rp_notef("", "replaying thread %d only; %d other recorded thread(s) "
                 "dropped (multi-thread replay is out of scope)",
                 RP_TID, RP_DROPPED_THREADS);

    for (i = 0; i < RP_NRECS; i++) {
        if (!RP_RECS[i].is_cb)      /* callbacks are driven by the shim */
            rp_do_call(&RP_RECS[i]);
    }

    incomplete = (RP_DROPPED_THREADS != 0 || RP_PLAN_INCOMPLETE != 0 ||
                  RP_PLANNED_SKIPS != 0 || rp_n_skipped != 0 ||
                  rp_n_mismatch != 0 ||
                  rp_n_called + rp_n_skipped != RP_EXPECTED_CALLS ||
                  rp_n_cb != RP_EXPECTED_CALLBACKS);

    printf("replay execution: %ld/%d called, %ld skipped, %ld/%d callbacks, "
           "%ld mismatches, %d dropped threads -> %s [%s]\n",
           rp_n_called, RP_EXPECTED_CALLS, rp_n_skipped,
           rp_n_cb, RP_EXPECTED_CALLBACKS, rp_n_mismatch,
           RP_DROPPED_THREADS, out,
           incomplete ? "INCOMPLETE" : "COMPLETE");
    if (incomplete) {
        fprintf(stderr, "replay: incomplete or mismatched replay; refusing "
                        "a successful exit\n");
        rc = 4;
    } else {
        printf("replay: exit 0 means only that every planned action executed "
               "completely; it is NOT an equivalence PASS. Compare the "
               "result trace against independent reference evidence.\n");
    }

cleanup:
    tr_shutdown();
    if (rp_mod)
        FreeLibrary(rp_mod);
    free(rp_dll_owned);
    free(rp_blob_owned);
    free(rp_arena);
    return rc;
}
