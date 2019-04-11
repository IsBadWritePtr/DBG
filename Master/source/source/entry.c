#include <ntapi.h>
#include <console.h>
#include <logger.h>
#include <master.h>

static PWSTR szCommandLine;
static DWORD dwXorshiftState;

static
DWORD
Fnv1a(
    IN QWORD qwData
    )
{
    #define FNV1_PRIME_32  0x01000193
    #define FNV1_OFFSET_32 0x811C9DC5

    DWORD dwHash = FNV1_OFFSET_32;

    for (ULONG i = 0; i != 8; i++) {
        dwHash *= FNV1_PRIME_32;
           dwHash ^= ((PBYTE)&qwData)[i];
    }

    #undef FNV1_PRIME_32 
    #undef FNV1_OFFSET_32

    return dwHash;
}

static
DWORD
Xorshift32(VOID)
{
	DWORD dw = dwXorshiftState;
	dw ^= dw << 13;
	dw ^= dw >> 17;
	dw ^= dw << 5;
    dwXorshiftState = dw;

	return dw;;
}

static
VOID
GenerateRandomPipeName(VOID)
{
    typedef struct _NGUID {
        ULONG  Data1;
        USHORT Data2;
        USHORT Data3;
        USHORT Data4;
        ULONG  Data5;
        USHORT Data6;
    } NGUID;

    NGUID Guid;

    if (IsProcessorFeaturePresent(PF_RDRAND_INSTRUCTION_AVAILABLE)) {
        __asm {
        #ifdef _AMD64_
        L1:
            rdrand rax
            jnc L1
        L2:
            rdrand rcx
            jnc L2

            mov qword ptr [0x00 + Guid], rax
            mov qword ptr [0x08 + Guid], rcx
        #else
        L1:
            rdrand eax
            jnc L1
        L2:
            rdrand ecx
            jnc L2

            mov dword ptr [0x00 + Guid], eax
            mov dword ptr [0x04 + Guid], ecx

        L3:
            rdrand eax
            jnc L3
        L4:
            rdrand ecx
            jnc L4

            mov dword ptr [0x08 + Guid], eax
            mov dword ptr [0x0C + Guid], ecx
        #endif

        L5:
            rdrand eax
            jnc L5
            mov word ptr [0x10 + Guid], ax
        };
    } else {
        #define USER_SHARED_DATA 0x7FFE0000

        dwXorshiftState = Fnv1a(*((PQWORD)(USER_SHARED_DATA + 0x008)) ^ *((PQWORD)(USER_SHARED_DATA + 0x014)) << 42);

        *((PDWORD)((ULONG_PTR)&Guid + 0x00)) = (DWORD)Xorshift32();
        *((PDWORD)((ULONG_PTR)&Guid + 0x04)) = (DWORD)Xorshift32();
        *((PDWORD)((ULONG_PTR)&Guid + 0x08)) = (DWORD)Xorshift32();
        *((PDWORD)((ULONG_PTR)&Guid + 0x0C)) = (DWORD)Xorshift32();
        *((PWORD )((ULONG_PTR)&Guid + 0x10)) = (WORD )Xorshift32();

        #undef USER_SHARED_DATA
    }

    printf("\nNew GUID: {%08lX-%04X-%04X-%04X-%08lX%04X}\n",
        Guid.Data1,
        Guid.Data2,
        Guid.Data3,
        Guid.Data4,
        Guid.Data5,
        Guid.Data6
    );
}

static
BOOL
NextCommand(
    OUT PWSTR* szCommand)
{
    if (!*szCommandLine) {
        return FALSE;
    }

    *szCommand = szCommandLine;

    if (*szCommandLine++ == '\"') {
        *szCommand = szCommandLine;

        while (*szCommandLine && *szCommandLine != '\"') {
            szCommandLine++;
        }
    } else {
        while (*szCommandLine && *szCommandLine != ' ') {
            szCommandLine++;
        }
    }

    if (*szCommandLine) {
        *szCommandLine++ = 0;

        while (*szCommandLine && *szCommandLine == ' ') { szCommandLine++; }
    }

    return TRUE;
}

static
BOOL
InitCommandLine(VOID)
{
    #define CMDX32(A) MAKELONG(L'/', A)

    PWSTR szCommand;
    BOOL bInvalidSyntax = FALSE;

    szCommandLine = GetCommandLineW();

    while (NextCommand(&szCommand)) {
        DWORD32 dwCommand = *((PDWORD32)szCommand);
        
        if (dwCommand == CMDX32(L'?')) {
            printf(
                "\nCommands:\n"
                "\t /?            \xB3 help\n"
                "\t /g            \xB3 generate random pipe name\n"
                "\t /n {pipename} \xB3 pipename, example: \\\\.\\PIPE\\{C05376A6-D8B9-4FDD-BD29-D5F27951166A}\n"
                "\t /f {path}     \xB3 logfle to write, if it doesn't exist will be created\n"
                "\t /F {path}     \xB3 logfile to append, if it doesn't exist will be created\n"
                "\n"
                "Keybinds:\n"
                "\t CTRL + C      \xB3 exit\n"
                "\t CTRL + L      \xB3 clear\n"
            );
        } else if (dwCommand == CMDX32(L'g')) {
            GenerateRandomPipeName();
        } else if (dwCommand == CMDX32(L'n')) {
            PWSTR szTemp;

            if (!NextCommand(&szTemp)) {
                bInvalidSyntax = TRUE;

                break;
            }
            
            InitMaster(szTemp);
        } else if (dwCommand == CMDX32(L'f')) {
            PWSTR szTemp;

            if (!NextCommand(&szTemp)) {
                bInvalidSyntax = TRUE;

                break;
            }
            
            if (!InitLogger(szTemp, FALSE)) {
                printf("\nInvalid file path!\n");

                return FALSE;
            }
        } else if (dwCommand == CMDX32(L'F')) {
            PWSTR szTemp;

            if (!NextCommand(&szTemp)) {
                bInvalidSyntax = TRUE;

                break;
            }
            
            if (!InitLogger(szTemp, TRUE)) {
                printf("\nInvalid file path!\n");

                return FALSE;
            }
        }
    }

    if (bInvalidSyntax) {
        printf("\nInvalid syntax on command \"%ls\"! Type /? for list of commands\n", szCommand);

        return FALSE;
    }

    #undef CMDX32

    return TRUE;
}

static
ULONG
WINAPI
KeyboardHook(VOID)
{
    #define VK_ASCII_L 0x4C

    DWORD dwUnused;
    INPUT_RECORD Input;
    BOOL bCtrlDown = GetAsyncKeyState(VK_CONTROL) >> 15;

    COORD ZeroCoord = {
        0, 0
    };

    CONSOLE_SCREEN_BUFFER_INFOEX ConsoleScreenBuffer = {
        sizeof(CONSOLE_SCREEN_BUFFER_INFOEX)
    };

    while (TRUE) { 
        if (!ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &Input, 1, &dwUnused)) {
            _asm {
                pause
            };

            continue;
        }

        if (Input.EventType == KEY_EVENT) {
            if (Input.Event.KeyEvent.bKeyDown) {
                if (Input.Event.KeyEvent.wVirtualKeyCode == VK_CONTROL) {
                    bCtrlDown = TRUE;
                } else if (bCtrlDown && Input.Event.KeyEvent.wVirtualKeyCode == VK_ASCII_L) {
                    if (GetConsoleScreenBufferInfoEx(ConsoleOutputHandle, &ConsoleScreenBuffer)) {
                        ULONG dwScreenSize = ConsoleScreenBuffer.dwSize.X * ConsoleScreenBuffer.dwSize.Y;

                        FillConsoleOutputCharacterW(ConsoleOutputHandle, 0x20, dwScreenSize, ZeroCoord, &dwUnused);
                        FillConsoleOutputAttribute(ConsoleOutputHandle, 0x07, dwScreenSize, ZeroCoord, &dwUnused);
                        SetConsoleCursorPosition(ConsoleOutputHandle, ZeroCoord);
                    }
                }
            } else {
                if (Input.Event.KeyEvent.wVirtualKeyCode == VK_CONTROL) {
                    bCtrlDown = FALSE;
                }
            }
        }
    } 

    #undef VK_ASCII_L
}

ULONG
WINAPI
Entry(VOID)
{
    if (!InitNtapi()      ) { return -1; }
    if (!InitConsole()    ) { return -2; }
    if (!InitCommandLine()) { return -3; }

    if (!MasterPipeName) {
        printf("No pipe name specified\n");

        return -4;
    }

    if (!CreateThread(NULL, 0, (PVOID)&KeyboardHook, NULL, 0, NULL)) {
        printf("Failed to hook the keyboard! You will be unable to clear the console\n");
    }

    StartMaster();
    ExitProcess(-5);

    return 0;
}
