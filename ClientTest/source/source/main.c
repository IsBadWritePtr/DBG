#include <stdio.h>
#include <windows.h>

#define CONST_STRING(X)         \
    {                           \
        sizeof(X) - sizeof(*X), \
        sizeof(X),              \
        X                       \
    }

#define CONST_UNICODE_STRING(X) CONST_STRING(X)
#define CONST_ANSI_STRING(X)    CONST_STRING(X)

typedef struct _UNICODE_STRING {
    USHORT v1;
    USHORT v2;
    PWSTR v3;
} UNICODE_STRING, *PUNICODE_STRING;

#include "dlogapi.h"

int
main()
{
    UNICODE_STRING PipeName = CONST_UNICODE_STRING(L"\\??\\pipe\\{6F9A9D97-3E66-767D-4C3C-C09739483C20}");

    $DLogInitialize(&PipeName, FALSE);

    for (ULONG i = 0; i != DLG_FILTER_COUNT; i++) {
        $DLogSendExGlobal(
            ($DLOGTYPE)(
                i | DLG_ATT_COLOURS | DLG_ATT_TICKS | DLG_ATT_PID | DLG_ATT_TID | DLG_ATT_ADDRESS | DLG_ATT_PROCNAME | DLG_ATT_PROCNAME_ALIGN(20)
            ),
            __PRETTY_FUNCTION__,
            "Low level independent logger"
        );
    }

    $DLogDestroy(FALSE);

    return 0;
}
