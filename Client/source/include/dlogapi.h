#ifndef _DLOGAPI_H
#define _DLOGAPI_H

#ifndef DLOGAPI
    #define DLOGAPI  __fastcall
#endif

#ifndef DLOGAPIX
    #define DLOGAPIX __cdecl
#endif

typedef enum _$DLOGTYPE {
    DLG_ATT_COLOURS  = 0x00010000,
    DLG_ATT_TICKS    = 0x00020000,
    DLG_ATT_PID      = 0x00040000,
    DLG_ATT_TID      = 0x00080000,
    DLG_ATT_ADDRESS  = 0x00100000,
    DLG_ATT_PROCNAME = 0x00200000,

    DLG_FLT_DEFAULT   = 0,
    DLG_FLT_INFO      = 1,
    DLG_FLT_WARNING   = 2,
    DLG_FLT_ERROR     = 3,
    DLG_FLT_CRITICAL  = 4,
    DLG_FLT_SUCCESS   = 5,
    DLG_FLT_HIGHLIGHT = 6,
    DLG_FILTER_COUNT
} $DLOGTYPE, *$PDLOGTYPE;

#define DLG_ATT_PROCNAME_ALIGN(X) ((X & 0xFF) << 24)

VOID
DLOGAPIX
$DLogSendExLocal(
    IN $DLOGTYPE Type,
    IN PSTR      szFunctioName,
    IN PCSTR     szFormat,
    IN ...
    );

VOID
DLOGAPIX
$DLogSendExGlobal(
    IN $DLOGTYPE Type,
    IN PSTR      szFunctioName,
    IN PCSTR     szFormat,
    IN ...
    );

VOID
DLOGAPIX
$DLogSendLocal(
    IN PCSTR szFormat,
    IN ...
    );

VOID
DLOGAPIX
$DLogSendGlobal(
    IN PCSTR szFormat,
    IN ...
    );

VOID
DLOGAPI
$DLogDestroy(
    IN BOOL bDestroyLocal
    );

VOID
DLOGAPI
$DLogInitialize(
    IN PUNICODE_STRING MasterPipeName,
    IN BOOL bCreateLocal
    );

#endif
