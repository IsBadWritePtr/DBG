#include <logger.h>
#include <ntapi.h>
#include <console.h>

static HANDLE hFileOutput = INVALID_HANDLE_VALUE;

static
VOID
FORCEINLINE
IoWrite(
    IN PVOID pBuffer,
    IN ULONG cbBuffer
    )
{
    ULONG cbBytesWritten;

    WriteFile(ConsoleOutputHandle, pBuffer, cbBuffer, &cbBytesWritten, NULL);

    if (hFileOutput != INVALID_HANDLE_VALUE) {
        WriteFile(hFileOutput, pBuffer, cbBuffer, &cbBytesWritten, NULL);
    }
}

VOID
LoggerPrint(
    IN PBYTE szBuffer,
    IN ULONG cbBuffer
    )
{
    PBYTE szBufferIndex = szBuffer;
    PBYTE szBufferEnd = szBuffer + cbBuffer;
    BOOL  bColourChanged = FALSE;

    while (szBuffer != szBufferEnd) {
        if (*szBuffer++ == 0xFF) {
            IoWrite(szBufferIndex, szBuffer - szBufferIndex - 1);
            SetConsoleTextAttribute(ConsoleOutputHandle, *szBuffer++);
            bColourChanged = TRUE;
            szBufferIndex = szBuffer;
        }
    }

    if (szBufferIndex < szBuffer) {
        IoWrite(szBufferIndex, szBuffer - szBufferIndex);
    }

    if (bColourChanged) {
        SetConsoleTextAttribute(ConsoleOutputHandle, 0x07);
    }

    IoWrite("\r\n", 2);
}

BOOL
InitLogger(
    IN PWSTR szFilePath,
    IN BOOL  bAppend
    )
{
    if (hFileOutput != INVALID_HANDLE_VALUE) {
        CloseHandle(hFileOutput);
    }

    hFileOutput = CreateFileW(
        szFilePath,
        GENERIC_WRITE,
        0,
        NULL,
        bAppend ? OPEN_ALWAYS : CREATE_ALWAYS,
        0,
        NULL
        );

    return (hFileOutput != INVALID_HANDLE_VALUE);
}
