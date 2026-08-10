/* shimforge selftest -- v2 ("new") ABI. Same behaviour, different shape.
 *
 * The delta a shim has to absorb:
 *   struct     OLD_BUF{u32 size; u8 *data; u32 len}
 *           -> NEW_BUF{u32 size; u32 version; u8 *data; u64 len}   (insert @4)
 *   signature  Process(h, buf, flags) -> Process2(h, buf, flags, reserved)
 *   errors     small negative ints -> HRESULT-like unsigned codes
 *   handles    Open returns the handle -> Open2 returns a status, handle out
 *   handles    a numerically disjoint handle space (0x0B... vs 0x0A...)
 *   callback   cb(h, pct) -> cb(h, pct, ctx)
 *   readback   Read2 prefixes the payload with the 4 byte format version
 *
 * The transform itself is bit identical to v1; if it were not, even a correct
 * shim would diverge and the rig would prove nothing.
 */

#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NEW_S_OK          ((int)0x00000000)
#define NEW_E_INVALIDARG  ((int)0x80070057)
#define NEW_E_HANDLE      ((int)0x80070006)
#define NEW_E_INSUFF      ((int)0x8007007A)
#define NEW_E_NOTINIT     ((int)0x800401F0)
#define NEW_E_UNEXPECTED  ((int)0x8000FFFF)

#define NEW_VERSION        0x00020001u
#define NEW_FORMAT_VERSION 2u          /* the value written into NEW_BUF.version */

typedef struct NEW_BUF {
    unsigned int       size;
    unsigned int       version;
    unsigned char     *data;
    unsigned long long len;
} NEW_BUF;

typedef struct NEW_STAT {
    unsigned int       size;
    unsigned int       version;
    unsigned long long nproc;
    unsigned long long nbytes;
    unsigned int       checksum;
    unsigned int       rsv;
    unsigned long long ticks;
} NEW_STAT;

typedef int (__stdcall *NEW_PROGRESS)(void *h, int pct, void *ctx);

/* The v2 delta the shim has to absorb, pinned so it stays a real delta:
 * `version` occupies the 4 bytes v1 spent on padding, and `len` is twice the
 * width it was. */
_Static_assert(offsetof(NEW_BUF, version) == 4, "version must land in v1 padding");
_Static_assert(offsetof(NEW_BUF, data) == 8, "NEW_BUF.data");
_Static_assert(offsetof(NEW_BUF, len) == 16, "NEW_BUF.len");
_Static_assert(sizeof(((NEW_BUF *)0)->len) == 8, "NEW_BUF.len must be widened");

#define SLOT_MAX   8
#define STASH_MAX  512

#define NEW_HANDLE_BASE 0x0B000000u
#define NEW_HANDLE_TAG  0x5A5u

typedef struct slot {
    int           used;
    unsigned int  mode;
    NEW_PROGRESS  cb;
    void         *cb_ctx;
    unsigned long long nproc;
    unsigned long long nbytes;
    unsigned int  checksum;
    unsigned int  stash_len;
    unsigned char stash[STASH_MAX];
} slot;

static slot g_slot[SLOT_MAX];
static int  g_init;

static void *slot_to_handle(int i)
{
    uintptr_t v = (uintptr_t)NEW_HANDLE_BASE
                + (uintptr_t)((unsigned int)(i + 1) * 0x1000u)
                + (uintptr_t)NEW_HANDLE_TAG;
    return (void *)v;
}

static int handle_to_slot(void *h)
{
    uintptr_t v = (uintptr_t)h;
    unsigned int off;
    int i;

    if (v < (uintptr_t)NEW_HANDLE_BASE)
        return -1;
    off = (unsigned int)(v - (uintptr_t)NEW_HANDLE_BASE);
    if (off > 0xFFFFFu || (off & 0xFFFu) != NEW_HANDLE_TAG)
        return -1;
    i = (int)(off >> 12) - 1;
    if (i < 0 || i >= SLOT_MAX || !g_slot[i].used)
        return -1;
    return i;
}

static void transform_range(unsigned char *p, unsigned int from,
                            unsigned int to, unsigned char key)
{
    unsigned int i;

    for (i = from; i < to; i++) {
        unsigned int v = (unsigned int)((p[i] + (unsigned char)(i * 31u + 7u)) & 0xFFu);
        v = ((v << 3) | (v >> 5)) & 0xFFu;
        p[i] = (unsigned char)(v ^ key);
    }
}

static unsigned int fold_into(unsigned int h, const unsigned char *p,
                              unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

int __stdcall Init2(const char *tag, unsigned int flags, void *reserved)
{
    (void)flags;
    (void)reserved;
    if (tag == NULL || tag[0] == '\0')
        return NEW_E_INVALIDARG;
    memset(g_slot, 0, sizeof(g_slot));
    g_init = 1;
    return NEW_S_OK;
}

int __stdcall Open2(const char *name, unsigned int mode, void **out_h)
{
    int i;

    if (out_h == NULL)
        return NEW_E_INVALIDARG;
    *out_h = NULL;
    if (!g_init)
        return NEW_E_NOTINIT;
    if (name == NULL || name[0] == '\0')
        return NEW_E_INVALIDARG;
    for (i = 0; i < SLOT_MAX; i++) {
        if (!g_slot[i].used)
            break;
    }
    if (i == SLOT_MAX)
        return NEW_E_UNEXPECTED;
    memset(&g_slot[i], 0, sizeof(g_slot[i]));
    g_slot[i].used = 1;
    g_slot[i].mode = mode;
    g_slot[i].checksum = 2166136261u;
    *out_h = slot_to_handle(i);
    return NEW_S_OK;
}

int __stdcall SetCallback2(void *h, NEW_PROGRESS cb, void *ctx)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return NEW_E_HANDLE;
    g_slot[i].cb = cb;
    g_slot[i].cb_ctx = ctx;
    return NEW_S_OK;
}

int __stdcall Process2(void *h, NEW_BUF *buf, int flags, void *reserved)
{
    int i = handle_to_slot(h);
    unsigned int n, mid;
    unsigned char key;

    if (i < 0)
        return NEW_E_HANDLE;
    if (reserved != NULL)
        return NEW_E_INVALIDARG;          /* reserved really is reserved */
    if (buf == NULL || buf->size != (unsigned int)sizeof(NEW_BUF))
        return NEW_E_INVALIDARG;
    if (buf->version != NEW_FORMAT_VERSION || buf->data == NULL)
        return NEW_E_INVALIDARG;
    if (buf->len > (unsigned long long)STASH_MAX)
        return NEW_E_INSUFF;
    n = (unsigned int)buf->len;

    key = (unsigned char)(((unsigned int)flags & 0xFFu) ^ 0xA5u);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 0, g_slot[i].cb_ctx);
    mid = n / 2u;
    transform_range(buf->data, 0, mid, key);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 50, g_slot[i].cb_ctx);
    transform_range(buf->data, mid, n, key);

    memcpy(g_slot[i].stash, buf->data, n);
    g_slot[i].stash_len = n;
    g_slot[i].nproc += 1u;
    g_slot[i].nbytes += n;
    g_slot[i].checksum = fold_into(g_slot[i].checksum, buf->data, n);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 100, g_slot[i].cb_ctx);
    return NEW_S_OK;
}

/* v2 readback is self describing: [u32 format version][payload].
 * `*out_len` counts the whole thing, tag included. A shim that forwards this
 * to a v1 caller has to strip the tag -- that omission is what
 * shim_bug_offset plants. */
int __stdcall Read2(void *h, unsigned char *out, unsigned int cap,
                    unsigned int *out_len)
{
    int i = handle_to_slot(h);
    unsigned int need;

    if (i < 0)
        return NEW_E_HANDLE;
    if (out == NULL || out_len == NULL)
        return NEW_E_INVALIDARG;
    if (g_slot[i].stash_len == 0)
        return NEW_E_UNEXPECTED;
    need = 4u + g_slot[i].stash_len;
    if (cap < need) {
        *out_len = need;
        return NEW_E_INSUFF;
    }
    memset(out, 0, cap);
    out[0] = (unsigned char)(NEW_FORMAT_VERSION & 0xFFu);
    out[1] = (unsigned char)((NEW_FORMAT_VERSION >> 8) & 0xFFu);
    out[2] = (unsigned char)((NEW_FORMAT_VERSION >> 16) & 0xFFu);
    out[3] = (unsigned char)((NEW_FORMAT_VERSION >> 24) & 0xFFu);
    memcpy(out + 4, g_slot[i].stash, g_slot[i].stash_len);
    *out_len = need;
    return NEW_S_OK;
}

int __stdcall GetStats2(void *h, NEW_STAT *st)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return NEW_E_HANDLE;
    if (st == NULL || st->size < (unsigned int)sizeof(NEW_STAT))
        return NEW_E_INVALIDARG;
    st->size = (unsigned int)sizeof(NEW_STAT);
    st->version = NEW_FORMAT_VERSION;
    st->nproc = g_slot[i].nproc;
    st->nbytes = g_slot[i].nbytes;
    st->checksum = g_slot[i].checksum;
    st->rsv = 0;
    st->ticks = ((unsigned long long)g_slot[i].nproc << 32)
              | (unsigned long long)g_slot[i].nbytes;
    return NEW_S_OK;
}

int __stdcall Close2(void *h)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return NEW_E_HANDLE;
    memset(&g_slot[i], 0, sizeof(g_slot[i]));
    return NEW_S_OK;
}

unsigned int __stdcall Version2(void)
{
    return NEW_VERSION;
}
