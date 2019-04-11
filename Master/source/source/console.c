#include <ntapi.h>
#include <console.h>

PVOID  ConsoleOutputBuffer;
HANDLE ConsoleOutputHandle;
CRITICAL_SECTION ConsoleOutputLock;

VOID
CDECL
printf(
    IN PSTR szFormat,
    IN ...
    )
{
    ULONG cbBytesWritten;

    ULONG cbBuffer = (ULONG)fnVsnprintf(
        ConsoleOutputBuffer,
        CFG_CB_CONSOLE_BUFFER,
        szFormat,
        (PVOID)((PULONG_PTR)&szFormat + 1)
        );

    if (cbBuffer) {
		if (!WriteFile(ConsoleOutputHandle, ConsoleOutputBuffer, cbBuffer, &cbBytesWritten, NULL)) {
			FatalAppExitW(0, L"Unexpected error at WriteFile");
		}
    }
}

BOOL
InitConsole(VOID)
{
    if (!(ConsoleOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE))) {
        return FALSE;
    }

    if (!(ConsoleOutputBuffer = VirtualAlloc(NULL, CFG_CB_CONSOLE_BUFFER, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        FatalAppExitW(0, L"Not enough memory!");

        return FALSE;
    }

    InitializeCriticalSection(&ConsoleOutputLock);

    return TRUE;;
}
