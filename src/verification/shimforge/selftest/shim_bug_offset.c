/* Negative fixture: the v2 format tag remains in readback data. */

#include <windows.h>
#include <stdint.h>
#include <string.h>

/* ---- v1 surface presented to the app ------------------------------------ */

#define OLD_OK           0
#define OLD_E_INVALID   (-1)
#define OLD_E_HANDLE    (-2)
#define OLD_E_STATE     (-3)
#define OLD_E_TOOSMALL  (-4)
#define OLD_E_NOTINIT   (-5)

#define OLD_VERSION      0x00010000u

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

/* ---- v2 surface consumed from newlib.dll -------------------------------- */

#define NEW_S_OK          ((int)0x00000000)
#define NEW_E_INVALIDARG  ((int)0x80070057)
#define NEW_E_HANDLE      ((int)0x80070006)
#define NEW_E_INSUFF      ((int)0x8007007A)
#define NEW_E_NOTINIT     ((int)0x800401F0)
#define NEW_E_UNEXPECTED  ((int)0x8000FFFF)

#define NEW_FORMAT_VERSION 2u

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

__declspec(dllimport) int __stdcall Init2(const char *tag, unsigned int flags,
                                          void *reserved);
__declspec(dllimport) int __stdcall Open2(const char *name, unsigned int mode,
                                          void **out_h);
__declspec(dllimport) int __stdcall SetCallback2(void *h, NEW_PROGRESS cb,
                                                 void *ctx);
__declspec(dllimport) int __stdcall Process2(void *h, NEW_BUF *buf, int flags,
                                             void *reserved);
__declspec(dllimport) int __stdcall Read2(void *h, unsigned char *out,
                                          unsigned int cap,
                                          unsigned int *out_len);
__declspec(dllimport) int __stdcall GetStats2(void *h, NEW_STAT *st);
__declspec(dllimport) int __stdcall Close2(void *h);
__declspec(dllimport) unsigned int __stdcall Version2(void);

/* ---- handle mapping ----------------------------------------------------- */

#define SLOT_MAX   8
#define STAGE_MAX  640          /* newlib stash (512) + tag, with headroom */

/* The shim mints its own v1 handles: it needs per-handle state (the app's
 * callback) and the v2 handle space is numerically disjoint anyway. */
#define SHIM_HANDLE_BASE 0x0C000000u
#define SHIM_HANDLE_TAG  0x9Bu

typedef struct shim_slot {
    int          used;
    void        *h2;            /* newlib handle */
    void        *hold;          /* v1 handle the app holds */
    OLD_PROGRESS cb;            /* app callback, v1 signature */
} shim_slot;

static shim_slot g_slot[SLOT_MAX];

static void *slot_to_handle(int i)
{
    uintptr_t v = (uintptr_t)SHIM_HANDLE_BASE
                + (uintptr_t)((unsigned int)(i + 1) * 0x100u)
                + (uintptr_t)SHIM_HANDLE_TAG;
    return (void *)v;
}

static shim_slot *find_slot(void *h)
{
    uintptr_t v = (uintptr_t)h;
    unsigned int off;
    int i;

    if (v < (uintptr_t)SHIM_HANDLE_BASE)
        return NULL;
    off = (unsigned int)(v - (uintptr_t)SHIM_HANDLE_BASE);
    if (off > 0xFFFFu || (off & 0xFFu) != SHIM_HANDLE_TAG)
        return NULL;
    i = (int)(off >> 8) - 1;
    if (i < 0 || i >= SLOT_MAX || !g_slot[i].used)
        return NULL;
    return &g_slot[i];
}

static int map_hr(int hr)
{
    switch (hr) {
    case NEW_S_OK:         return OLD_OK;
    case NEW_E_INVALIDARG: return OLD_E_INVALID;
    case NEW_E_HANDLE:     return OLD_E_HANDLE;
    case NEW_E_INSUFF:     return OLD_E_TOOSMALL;
    case NEW_E_NOTINIT:    return OLD_E_NOTINIT;
    default:               return OLD_E_STATE;
    }
}

/* v2 hands the callback a v2 handle plus a context. The app has never seen
 * either, so translate back to the handle it was given. */
static int __stdcall progress_thunk(void *h2, int pct, void *ctx)
{
    shim_slot *sl = (shim_slot *)ctx;

    (void)h2;
    if (sl == NULL || sl->cb == NULL)
        return 0;
    return sl->cb(sl->hold, pct);
}

/* ---- v1 entry points ---------------------------------------------------- */

int __stdcall Init(const char *tag, void *reserved)
{
    int hr;

    if (tag == NULL || tag[0] == '\0')
        return OLD_E_INVALID;
    memset(g_slot, 0, sizeof(g_slot));
    hr = Init2(tag, 0u, reserved);
    return map_hr(hr);
}

void * __stdcall Open(const char *name, unsigned int mode)
{
    void *h2 = NULL;
    int hr, i;

    hr = Open2(name, mode, &h2);
    if (hr != NEW_S_OK) {
        /* v1 signalled failure through GetLastError, v2 through the status. */
        if (hr == NEW_E_INVALIDARG)
            SetLastError(ERROR_INVALID_NAME);
        else if (hr == NEW_E_NOTINIT)
            SetLastError(ERROR_NOT_READY);
        else
            SetLastError(ERROR_NO_MORE_ITEMS);
        return NULL;
    }
    for (i = 0; i < SLOT_MAX; i++) {
        if (!g_slot[i].used)
            break;
    }
    if (i == SLOT_MAX) {
        Close2(h2);
        SetLastError(ERROR_NO_MORE_ITEMS);
        return NULL;
    }
    g_slot[i].used = 1;
    g_slot[i].h2 = h2;
    g_slot[i].hold = slot_to_handle(i);
    g_slot[i].cb = NULL;
    SetLastError(ERROR_SUCCESS);
    return g_slot[i].hold;
}

int __stdcall SetCallback(void *h, OLD_PROGRESS cb)
{
    shim_slot *sl = find_slot(h);

    if (sl == NULL)
        return OLD_E_HANDLE;
    sl->cb = cb;
    if (cb == NULL)
        return map_hr(SetCallback2(sl->h2, NULL, NULL));
    return map_hr(SetCallback2(sl->h2, progress_thunk, sl));
}

int __stdcall Process(void *h, OLD_BUF *buf, int flags)
{
    shim_slot *sl = find_slot(h);
    NEW_BUF nb;
    int hr;

    if (sl == NULL)
        return OLD_E_HANDLE;
    /* Validate against the v1 rules before reshaping: a v1 caller must get
     * the v1 rejection, not whatever v2 makes of a half built struct. */
    if (buf == NULL || buf->size != (unsigned int)sizeof(OLD_BUF))
        return OLD_E_INVALID;
    if (buf->data == NULL)
        return OLD_E_INVALID;

    memset(&nb, 0, sizeof(nb));
    nb.size = (unsigned int)sizeof(NEW_BUF);
    nb.version = NEW_FORMAT_VERSION;
    nb.data = buf->data;
    nb.len = (unsigned long long)buf->len;
    hr = Process2(sl->h2, &nb, flags, NULL);
    if (hr != NEW_S_OK)
        return map_hr(hr);
    buf->len = (unsigned int)nb.len;
    return OLD_OK;
}

int __stdcall Read(void *h, unsigned char *out, unsigned int cap,
                   unsigned int *out_len)
{
    shim_slot *sl = find_slot(h);
    unsigned char stage[STAGE_MAX];
    unsigned int want, got = 0, avail;
    int hr;

    if (sl == NULL)
        return OLD_E_HANDLE;
    if (out == NULL || out_len == NULL)
        return OLD_E_INVALID;

    /* Ask v2 for room for the tag on top of what the v1 caller offered,
     * otherwise a caller sized exactly to the payload would spuriously fail. */
    want = cap;
    if (want > (unsigned int)sizeof(stage) - 4u)
        want = (unsigned int)sizeof(stage) - 4u;
    want += 4u;

    hr = Read2(sl->h2, stage, want, &got);
    if (hr == NEW_E_INSUFF) {
        *out_len = (got >= 4u) ? got - 4u : 0u;
        return OLD_E_TOOSMALL;
    }
    if (hr != NEW_S_OK)
        return map_hr(hr);

    avail = (got >= 4u) ? got - 4u : 0u;
    if (cap < avail) {
        *out_len = avail;
        return OLD_E_TOOSMALL;
    }
    memset(out, 0, cap);
    /* Exercise byte-offset mismatch detection. */
    memcpy(out, stage, avail);
    *out_len = avail;
    return OLD_OK;
}

int __stdcall GetStats(void *h, OLD_STAT *st)
{
    shim_slot *sl = find_slot(h);
    NEW_STAT ns;
    int hr;

    if (sl == NULL)
        return OLD_E_HANDLE;
    if (st == NULL || st->size < (unsigned int)sizeof(OLD_STAT))
        return OLD_E_INVALID;

    memset(&ns, 0, sizeof(ns));
    ns.size = (unsigned int)sizeof(NEW_STAT);
    hr = GetStats2(sl->h2, &ns);
    if (hr != NEW_S_OK)
        return map_hr(hr);
    st->size = (unsigned int)sizeof(OLD_STAT);
    st->nproc = (unsigned int)ns.nproc;
    st->nbytes = (unsigned int)ns.nbytes;
    st->checksum = ns.checksum;
    st->ticks = ns.ticks;
    return OLD_OK;
}

int __stdcall Close(void *h)
{
    shim_slot *sl = find_slot(h);
    int hr;

    if (sl == NULL)
        return OLD_E_HANDLE;
    hr = Close2(sl->h2);
    memset(sl, 0, sizeof(*sl));
    return map_hr(hr);
}

unsigned int __stdcall Version(void)
{
    /* Touch v2 so the reported version is not a hard coded lie, but keep
     * presenting the v1 number: the app is a v1 consumer. */
    (void)Version2();
    return OLD_VERSION;
}
