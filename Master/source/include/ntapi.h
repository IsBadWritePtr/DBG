#ifndef _NTAPI_H
#define _NTAPI_H

extern
INT
(CDECL *fnVsnprintf)(
    OUT PSTR  szBuffer,
    IN  ULONG cbBuffer,
    IN  PSTR  szFormat,
    IN  PVOID ArgsBase
    );

BOOL
InitNtapi(VOID);

#endif
