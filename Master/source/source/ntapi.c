#include <ntapi.h>

INT
(CDECL *fnVsnprintf)(
    OUT PSTR  szBuffer,
    IN  ULONG cbBuffer,
    IN  PSTR  szFormat,
    IN  PVOID ArgsBase
    );

BOOL
InitNtapi(VOID)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");

    if (!Ntdll) {
        return FALSE;
    }

    return (fnVsnprintf = (PVOID)GetProcAddress(Ntdll, "_vsnprintf" )) ? TRUE : FALSE;
}
