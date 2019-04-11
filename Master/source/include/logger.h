#ifndef _LOGGER_H
#define _LOGGER_H

VOID
LoggerPrint(
    IN PBYTE szBuffer,
    IN ULONG cbBuffer
    );

BOOL
InitLogger(
    IN PWSTR szFilePath,
    IN BOOL  bAppend
    );

#endif
