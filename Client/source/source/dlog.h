#ifndef _DLOG_H
#define _DLOG_H

#pragma warning(disable:137)
#pragma warning(disable:1899)

#define CFG_CB_READ_BUFFER  4
#define CFG_CB_WRITE_BUFFER 0x1000
#define CFG_TLS_INDEX       61

#ifdef DEBUG
    #include <stdio.h>
#endif

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#define IO
#define NON
#define OPT

#ifdef DEBUG
    #define DBGPRINTF printf
#else
    #define DBGPRINTF __noop
#endif

#define INLINEDLOGAPI __forceinline __fastcall
#define DLOGAPI       __fastcall
#define DLOGAPIX      __cdecl

#define CONST_STRING(X)         \
    {                           \
        sizeof(X) - sizeof(*X), \
        sizeof(X),              \
        X                       \
    }

#define CONST_UNICODE_STRING(X) CONST_STRING(X)
#define CONST_ANSI_STRING(X)    CONST_STRING(X)

#define IS_NULL(X)  (!((ULONG_PTR)(X)))
#define NOT_NULL(X) ((ULONG_PTR)(X))

#define IS_INVALID_HANDLE(X)  ((ULONG_PTR)(X) == (ULONG_PTR)INVALID_HANDLE_VALUE)
#define NOT_INVALID_HANDLE(X) ((ULONG_PTR)(X) != (ULONG_PTR)INVALID_HANDLE_VALUE)

/* to standup */
#define ERROREXIT(ECODE)      \
    __asm { mov eax, ECODE }; \
    __asm { int3           }; \
    __asm { hlt            }  

enum ERRORCODES {
    ERRORCODE_NO_NTDLL                = -1,
    ERRORCODE_NOT_ALL_PROC_FOUND      = -2,
    ERRORCODE_NTALLOCATEVIRTUALMEMORY = -3,
    ERRORCODE_NTCREATEFILE            = -4,
    ERRORCODE_NTWRITEFILE             = -5,
    ERRORCODE_NTREADFILE              = -6,
    ERRORCODE_NTFREEVIRTUALMEMORY     = -7,
    ERRORCODE_NTCLOSE                 = -8
};

#include <dlogapi.h>
#include "ntapi.h"

#endif
