/* tr_record.h -- JSONL trace writer used by generated taps.
 *
 * The wire format is owned by tools/shimforge/trace.py; this writer is its
 * only producer, so any change here must be mirrored there first.
 *
 * Usage from a generated thunk:
 *
 *     tr_call *c = tr_enter("Process", 0);
 *     tr_in_i64(c, "flags", flags, "i32");
 *     r = real_Process(...);
 *     tr_out_ptr(c, "buf", buf, extent);
 *     tr_ret_i64(c, r, "i32");
 *     tr_leave(c);
 *
 * Every entry point tolerates a NULL tr_call, so a thunk needs no branches
 * when recording is off. All in-args must be logged before the first
 * out-arg; the emitter cannot reopen a closed section.
 *
 * Environment:
 *   TAP_TRACE        output path; overrides the `path` argument of tr_init.
 *   TAP_PASSTHROUGH  "1" disables recording entirely (tr_enabled() == 0).
 *   TAP_LABEL        overrides the `label` argument of tr_init.
 *   TAP_MAXCAP       max bytes captured per pointer/string (default 64 KiB).
 *                    The effective value is stamped into header.maxcap.
 *   TAP_SUBJECT_SHA256
 *                    SHA-256 of the DLL whose behaviour is being recorded.
 *                    Exactly 64 hex digits are normalized to lowercase and
 *                    stamped into header.subject. Missing/invalid values are
 *                    omitted so evidence validation can fail closed.
 */

#ifndef SHIMFORGE_TR_RECORD_H
#define SHIMFORGE_TR_RECORD_H

#ifdef __cplusplus
extern "C" {
#endif

/* Reported in the header line as "tap". Bump on any wire-visible change. */
#define TR_TAP_VERSION "0.3"

/* Per-thread parent-seq stack. Calls nested deeper still get recorded, but
   their parent link is clamped to the deepest tracked frame. */
#define TR_MAX_DEPTH 32

/* Default ceiling for a single pointer or string capture. Override with
   -DTR_MAX_CAPTURE=... at build time or TAP_MAXCAP at run time. */
#ifndef TR_MAX_CAPTURE
#define TR_MAX_CAPTURE (64 * 1024)
#endif

typedef struct tr_call tr_call;

/* Opens a same-directory partial trace and writes the header line. Idempotent:
   later calls are ignored. The requested path is first invalidated and is
   replaced atomically only at a successful tr_shutdown. */
/* contract_sha256 is written as header.contract; NULL omits the field. The
   subject hash is read centrally from TAP_SUBJECT_SHA256. */
void tr_init(const char *path, const char *module, const char *arch,
             const char *label, const char *contract_sha256);
/* Writes the final integrity footer (payload-record count, preceding raw-byte
   count and SHA-256) only when no call is still in flight and no recorder
   fault/drop has ever occurred. It then flushes, commits and closes the
   partial before atomically promoting it. A crash, forced exit,
   allocation/TLS/serialization error, short write, failed flush/commit/close,
   or lost/corrupted line therefore cannot make the requested path complete. */
void tr_shutdown(void);
int  tr_enabled(void);

/* is_callback selects record type "k" instead of "c" and links the record to
   the enclosing call on this thread. Returns NULL when recording is off. */
tr_call *tr_enter(const char *sym, int is_callback);

/* `kind` is a model.ALL_KINDS name ("i32", "u64", "handle", ...); NULL means
   "i64". Fixed-width kinds are normalized to that width so that a sign
   extension in the thunk cannot show up as a diff. */
void tr_in_i64 (tr_call *c, const char *name, long long v, const char *kind);
void tr_in_f64 (tr_call *c, const char *name, double v);

/* nbytes < 0 means "deliberately not captured": the record carries n=0 and no
   byte string, which the scoring layer reads as missing verification credit
   rather than as a match. Unreadable memory is recorded the same way, with a
   note; the recorder never faults on a bad pointer. */
void tr_in_ptr (tr_call *c, const char *name, const void *p, long long nbytes);
void tr_in_str (tr_call *c, const char *name, const char *s);
void tr_in_wstr(tr_call *c, const char *name, const unsigned short *s);

void tr_out_i64(tr_call *c, const char *name, long long v, const char *kind);
void tr_out_f64(tr_call *c, const char *name, double v);
void tr_out_ptr(tr_call *c, const char *name, const void *p, long long nbytes);
void tr_out_str(tr_call *c, const char *name, const char *s);
void tr_out_wstr(tr_call *c, const char *name, const unsigned short *s);

void tr_ret_i64(tr_call *c, long long v, const char *kind);
void tr_ret_f64(tr_call *c, double v);
void tr_ret_void(tr_call *c);
void tr_lasterr(tr_call *c, unsigned long err);

/* Standalone diagnostic line. Consumes a seq so it stays ordered against the
   calls around it. */
void tr_note(const char *sym, const char *msg);

/* Emits the record and releases the frame. */
void tr_leave(tr_call *c);

#ifdef __cplusplus
}
#endif

#endif /* SHIMFORGE_TR_RECORD_H */
