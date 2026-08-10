/* shimforge selftest -- v1 ("old") ABI, the behaviour a shim must preserve.
 *
 * Small but real: handle table, in-place byte transform, progress callback,
 * cbSize-style stats struct. A trace differential only proves anything if the
 * bytes crossing the boundary actually change, so nothing here is a stub.
 *
 * Single threaded on purpose. The app is single threaded and adding a lock
 * would only add a nondeterministic ordering the normalizer would have to
 * paper over.
 *
 * Exports come from oldlib.def only (no __declspec(dllexport)) so that the
 * ordinal / NONAME assignment is exact and reproducible in the shims.
 */

#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OLD_OK           0
#define OLD_E_INVALID   (-1)
#define OLD_E_HANDLE    (-2)
#define OLD_E_STATE     (-3)
#define OLD_E_TOOSMALL  (-4)
#define OLD_E_NOTINIT   (-5)

#define OLD_VERSION      0x00010000u

typedef struct OLD_BUF {
    unsigned int   size;        /* = sizeof(OLD_BUF), caller set */
    unsigned char *data;
    unsigned int   len;
} OLD_BUF;

typedef struct OLD_STAT {
    unsigned int       size;    /* = sizeof(OLD_STAT), caller set */
    unsigned int       nproc;
    unsigned int       nbytes;
    unsigned int       checksum;
    unsigned long long ticks;   /* deterministic state stamp for verification */
} OLD_STAT;

typedef int (__stdcall *OLD_PROGRESS)(void *h, int pct);

/* contract.json hand-declares this layout. If the compiler ever disagrees the
 * rig would be masking and comparing the wrong byte ranges while still
 * looking green, so make the drift a build failure instead. */
_Static_assert(sizeof(OLD_BUF) == 24, "contract.json structs.OLD_BUF.size");
_Static_assert(offsetof(OLD_BUF, size) == 0, "contract.json OLD_BUF.size.off");
_Static_assert(offsetof(OLD_BUF, data) == 8, "contract.json OLD_BUF.data.off");
_Static_assert(offsetof(OLD_BUF, len) == 16, "contract.json OLD_BUF.len.off");
_Static_assert(sizeof(OLD_STAT) == 24, "contract.json structs.OLD_STAT.size");
_Static_assert(offsetof(OLD_STAT, nproc) == 4, "contract.json OLD_STAT.nproc.off");
_Static_assert(offsetof(OLD_STAT, nbytes) == 8, "contract.json OLD_STAT.nbytes.off");
_Static_assert(offsetof(OLD_STAT, checksum) == 12, "contract.json OLD_STAT.checksum.off");
_Static_assert(offsetof(OLD_STAT, ticks) == 16, "contract.json OLD_STAT.ticks.off");

#define SLOT_MAX   8
#define STASH_MAX  512

/* Handle values are opaque to the caller but deliberately fixed and
 * v1-specific, so that a shim built on v2 cannot pass the v2 handle through
 * unchanged -- the trace differential has to survive a real handle remap. */
#define OLD_HANDLE_BASE 0x0A000000u
#define OLD_HANDLE_TAG  0x37u

typedef struct slot {
    int           used;
    unsigned int  mode;
    OLD_PROGRESS  cb;
    unsigned int  nproc;
    unsigned int  nbytes;
    unsigned int  checksum;
    unsigned int  stash_len;
    unsigned char stash[STASH_MAX];
} slot;

static slot g_slot[SLOT_MAX];
static int  g_init;

static void *slot_to_handle(int i)
{
    uintptr_t v = (uintptr_t)OLD_HANDLE_BASE
                + (uintptr_t)((unsigned int)(i + 1) * 0x100u)
                + (uintptr_t)OLD_HANDLE_TAG;
    return (void *)v;
}

static int handle_to_slot(void *h)
{
    uintptr_t v = (uintptr_t)h;
    unsigned int off;
    int i;

    if (v < (uintptr_t)OLD_HANDLE_BASE)
        return -1;
    off = (unsigned int)(v - (uintptr_t)OLD_HANDLE_BASE);
    if (off > 0xFFFFu || (off & 0xFFu) != OLD_HANDLE_TAG)
        return -1;
    i = (int)(off >> 8) - 1;
    if (i < 0 || i >= SLOT_MAX || !g_slot[i].used)
        return -1;
    return i;
}

/* The transform is split so the caller can be told about progress at a real
 * half-way point rather than at a fabricated one. */
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

int __stdcall Init(const char *tag, void *reserved)
{
    /* `reserved` is opaque to the DLL and is never dereferenced. The closed
     * self-test nevertheless knows its concrete call-site object is 8 bytes,
     * which is the scenario extent recorded by contract.json. */
    (void)reserved;
    if (tag == NULL || tag[0] == '\0')
        return OLD_E_INVALID;
    memset(g_slot, 0, sizeof(g_slot));
    g_init = 1;
    return OLD_OK;
}

void * __stdcall Open(const char *name, unsigned int mode)
{
    int i;

    if (!g_init) {
        SetLastError(ERROR_NOT_READY);
        return NULL;
    }
    if (name == NULL || name[0] == '\0') {
        SetLastError(ERROR_INVALID_NAME);
        return NULL;
    }
    for (i = 0; i < SLOT_MAX; i++) {
        if (!g_slot[i].used)
            break;
    }
    if (i == SLOT_MAX) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return NULL;
    }
    memset(&g_slot[i], 0, sizeof(g_slot[i]));
    g_slot[i].used = 1;
    g_slot[i].mode = mode;
    g_slot[i].checksum = 2166136261u;
    SetLastError(ERROR_SUCCESS);
    return slot_to_handle(i);
}

int __stdcall SetCallback(void *h, OLD_PROGRESS cb)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return OLD_E_HANDLE;
    g_slot[i].cb = cb;
    return OLD_OK;
}

int __stdcall Process(void *h, OLD_BUF *buf, int flags)
{
    int i = handle_to_slot(h);
    unsigned int n, mid;
    unsigned char key;

    if (i < 0)
        return OLD_E_HANDLE;
    if (buf == NULL || buf->size != (unsigned int)sizeof(OLD_BUF))
        return OLD_E_INVALID;
    if (buf->data == NULL)
        return OLD_E_INVALID;
    n = buf->len;
    if (n > STASH_MAX)
        return OLD_E_TOOSMALL;

    key = (unsigned char)(((unsigned int)flags & 0xFFu) ^ 0xA5u);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 0);
    mid = n / 2u;
    transform_range(buf->data, 0, mid, key);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 50);
    transform_range(buf->data, mid, n, key);

    memcpy(g_slot[i].stash, buf->data, n);
    g_slot[i].stash_len = n;
    g_slot[i].nproc += 1u;
    g_slot[i].nbytes += n;
    g_slot[i].checksum = fold_into(g_slot[i].checksum, buf->data, n);
    if (g_slot[i].cb)
        g_slot[i].cb(h, 100);
    return OLD_OK;
}

int __stdcall Read(void *h, unsigned char *out, unsigned int cap,
                   unsigned int *out_len)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return OLD_E_HANDLE;
    if (out == NULL || out_len == NULL)
        return OLD_E_INVALID;
    if (g_slot[i].stash_len == 0)
        return OLD_E_STATE;
    if (cap < g_slot[i].stash_len) {
        /* Report the needed size and leave `out` untouched -- the caller's
         * buffer stays whatever it already was, which keeps the recorded
         * bytes deterministic as long as the caller zeroed it. */
        *out_len = g_slot[i].stash_len;
        return OLD_E_TOOSMALL;
    }
    memset(out, 0, cap);
    memcpy(out, g_slot[i].stash, g_slot[i].stash_len);
    *out_len = g_slot[i].stash_len;
    return OLD_OK;
}

int __stdcall GetStats(void *h, OLD_STAT *st)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return OLD_E_HANDLE;
    if (st == NULL || st->size < (unsigned int)sizeof(OLD_STAT))
        return OLD_E_INVALID;
    st->size = (unsigned int)sizeof(OLD_STAT);
    st->nproc = g_slot[i].nproc;
    st->nbytes = g_slot[i].nbytes;
    st->checksum = g_slot[i].checksum;
    st->ticks = ((unsigned long long)g_slot[i].nproc << 32)
              | (unsigned long long)g_slot[i].nbytes;
    return OLD_OK;
}

int __stdcall Close(void *h)
{
    int i = handle_to_slot(h);

    if (i < 0)
        return OLD_E_HANDLE;
    memset(&g_slot[i], 0, sizeof(g_slot[i]));
    return OLD_OK;
}

unsigned int __stdcall Version(void)
{
    return OLD_VERSION;
}
