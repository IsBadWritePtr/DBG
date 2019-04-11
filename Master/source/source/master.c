#include <ntapi.h>
#include <master.h>
#include <logger.h>
#include <console.h>

PWSTR MasterPipeName = NULL;

static
ULONG
WINAPI
ClientHandle(
    IN HANDLE hPipe
    )
{
    ULONG cbBytesRW;
    ULONG_PTR cbBuffer = CFG_CB_READ_BUFFER;
    PVOID pBuffer = NULL;

    if (!(pBuffer = VirtualAlloc(NULL, (SIZE_T)cbBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        ConsoleLockOuput();
        printf("# Not enough memory to accept a new client!\n");
        ConsoleReleaseOuput();
      
        return 0;
    }

    ConsoleLockOuput();
    printf("# New client 0x%p\n", hPipe);
    ConsoleReleaseOuput();

    while (ReadFile(hPipe, pBuffer, CFG_CB_READ_BUFFER, &cbBytesRW, NULL)) {
        ConsoleLockOuput();
        LoggerPrint(pBuffer, cbBytesRW);
        ConsoleReleaseOuput();

        if (!WriteFile(hPipe, pBuffer, CFG_CB_WRITE_BUFFER, &cbBytesRW, NULL)) {
            break;
        }
    }

    ConsoleLockOuput();
    printf("# Lost connection with 0x%p\n", hPipe);
    ConsoleReleaseOuput();

    VirtualFree(pBuffer, 0, MEM_RELEASE);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}

BOOL
StartMaster(VOID)
{
    HANDLE hMasterPipe;

    while (TRUE) {
        hMasterPipe = CreateNamedPipeW(
            MasterPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            CFG_CB_WRITE_BUFFER,
            CFG_CB_READ_BUFFER,
            INFINITE,
            NULL
            );

        if (hMasterPipe == INVALID_HANDLE_VALUE) {
            ConsoleLockOuput();
            printf("# Failed to create new pipe\n");
            ConsoleReleaseOuput();

            return FALSE;
        }

        if (!ConnectNamedPipe(hMasterPipe, NULL)) {
            CloseHandle(hMasterPipe);
            ConsoleLockOuput();
            printf("# Failed to accept new connection\n");
            ConsoleReleaseOuput();

            continue;
        }

        if (!CreateThread(NULL, 0, ClientHandle, hMasterPipe, 0, NULL)) {
            DisconnectNamedPipe(hMasterPipe);
            CloseHandle(hMasterPipe);
            ConsoleLockOuput();
            printf("# Failed to create new thread\n");
            ConsoleReleaseOuput();
        }
    }
}
