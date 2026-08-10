/* Failure-injection driver for runtime/tr_record.c.
 *
 * Compile tr_record.c with -DTR_TEST_FAULT_INJECT.  The Python regression
 * launches one fresh process per injected site so sticky global state cannot
 * leak between cases.
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include "tr_record.h"

static const char CONTRACT_SHA[] =
    "1111111111111111111111111111111111111111111111111111111111111111";

int main(void)
{
    tr_call *c;
    char byte = 0x2a;
    wchar_t mode[16];
    DWORD n;

    tr_init(NULL, "faulttest.dll",
#if defined(_M_IX86) || defined(__i386__)
            "x86",
#else
            "x64",
#endif
            NULL, CONTRACT_SHA);
    if (tr_enabled()) {
        n = GetEnvironmentVariableW(L"SHIMFORGE_TR_MODE", mode,
                                    (DWORD)(sizeof mode / sizeof mode[0]));
        if (n == 4 && n < (DWORD)(sizeof mode / sizeof mode[0]) &&
            !lstrcmpW(mode, L"note"))
            tr_note("Ping", "injected diagnostic");
        c = tr_enter("Ping", 0);
        if (c) {
            if (n == 7 && n < (DWORD)(sizeof mode / sizeof mode[0]) &&
                !lstrcmpW(mode, L"unknown"))
                tr_in_ptr(c, "p", &byte, -1);
            else
                tr_in_i64(c, "x", 42, "i32");
            tr_ret_i64(c, 42, "i32");
            tr_leave(c);
        }
    }
    tr_shutdown();
    return 0;
}
