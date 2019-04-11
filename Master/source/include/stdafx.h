
#ifdef _M_AMD64
    #define _AMD64_
#elif _M_IX86
    #define _X86_
#endif

#define _WIN32_WINNT_WIN7 0x0601
#define _WIN32_IE_WIN7    0x0800

#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define _WIN32_IE    _WIN32_IE_WIN7

#include <winternl.h>
#include <winbase.h>
#include <winuser.h>
#include <consoleapi.h>
#include <consoleapi2.h>
#include <consoleapi3.h>
#include <config.h>

#define IO
#define NON
#define OPT

#ifdef VOID
    #undef VOID
#endif

#ifdef CDECL
    #undef CDECL
#endif

#define CDECL __cdecl

typedef void VOID;
typedef unsigned __int64 QWORD, *PQWORD;

#pragma warning(disable:537)
