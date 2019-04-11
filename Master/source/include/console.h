#ifndef _CONSOLE_H
#define _CONSOLE_H

extern PVOID  ConsoleOutputBuffer;
extern HANDLE ConsoleOutputHandle;
extern CRITICAL_SECTION ConsoleOutputLock;

static
VOID
FORCEINLINE
ConsoleLockOuput(VOID)
{
    EnterCriticalSection(&ConsoleOutputLock);
}

static
VOID
FORCEINLINE
ConsoleReleaseOuput(VOID)
{
    LeaveCriticalSection(&ConsoleOutputLock);
}

VOID
CDECL
printf(
    IN PSTR szFormat,
    IN ...
    );

BOOL
InitConsole(VOID);

#endif
