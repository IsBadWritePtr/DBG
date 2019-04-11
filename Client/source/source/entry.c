#include "dlog.h"

typedef struct _TEB_FIX {
    PVOID Reserved1[8];
    CLIENT_ID ClientId; // Added
    PVOID Reserved2[2];
    PPEB ProcessEnvironmentBlock;
    PVOID Reserved3[399];
    BYTE Reserved4[1952];
    PVOID TlsSlots[64];
    BYTE Reserved5[8];
    PVOID Reserved6[26];
    PVOID ReservedForOle;  // Windows 2000 only
    PVOID Reserved7[4];
    PVOID TlsExpansionSlots;
} TEB_FIX, *PTEB_FIX;

typedef struct _PEB_LDR_DATA_FIX {
    BYTE Reserved1[8];
    PVOID Reserved2[1];
    LIST_ENTRY InLoadOrderModuleList; // Added
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_FIX, *PPEB_LDR_DATA_FIX;

typedef struct _LDR_DATA_TABLE_ENTRY_FIX {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName; // Added
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FIX, *PLDR_DATA_TABLE_ENTRY_FIX;


static BOOL bFunctionsInited = FALSE;

static
DWORD
INLINEDLOGAPI
$RtlpGetTickCount(VOID)
{
    return *(volatile DWORD*)(0x7FFE0000 + 0x320);
}

static
BOOL
INLINEDLOGAPI
$RtlpCompareUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2
    )
{
    if (String1->Length == String2->Length) {
        PWSTR szBuffer1 = String1->Buffer;
        PWSTR szBuffer2 = String2->Buffer;

        while (*szBuffer1 == *szBuffer2) {
            if (!*szBuffer1) {
                return TRUE;
            }

            szBuffer1++;
            szBuffer2++;
        }    
    }

    return FALSE;
}

static
BOOL
INLINEDLOGAPI
$RtlpCompareStringZ(
    IN PSTR szString1,
    IN PSTR szString2
    )
{
    while (*szString1== *szString2) {
        if (!*szString1) {
            return TRUE;
        }

        szString1++;
        szString2++;
    }    

    return FALSE;
}

static
PTEB_FIX
INLINEDLOGAPI
$RtlpGetTeb(VOID)
{
    __asm {
    #ifdef _AMD64_
        mov rax, qword ptr gs:[0x30]
    #else
        mov eax, dword ptr fs:[0x18]
    #endif
    };
}

static
HMODULE
INLINEDLOGAPI
$DLogGetNtdll(VOID)
{
    DBGPRINTF("Finding ntdll.dll address\n");

    PPEB_LDR_DATA_FIX PebLdr = (PVOID)$RtlpGetTeb()->ProcessEnvironmentBlock->Ldr;
    PLDR_DATA_TABLE_ENTRY_FIX Index = (PVOID)PebLdr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY_FIX End   = (PVOID)PebLdr->InLoadOrderModuleList.Flink;
    UNICODE_STRING szNtdll = CONST_UNICODE_STRING(L"ntdll.dll");

    do {
        if ($RtlpCompareUnicodeString(&Index->BaseDllName, &szNtdll)) {
            DBGPRINTF("\t%ls = 0x%p\n", Index->BaseDllName.Buffer, Index->DllBase);

            return Index->DllBase;
        }

        Index = (PVOID)Index->InLoadOrderModuleList.Flink;
    } while (Index != End);

    DBGPRINTF("\tFailed to find ntdll.dll!\n");
    ERROREXIT(ERRORCODE_NO_NTDLL);
}

static
VOID
DLOGAPI
$DLogInitializeFunctions(VOID)
{
    PSTR szFunctions[] = {
        "NtReadFile",
        "NtWriteFile",
        "NtCreateFile",
        "NtFreeVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtClose",
        "_vsnprintf"
    };

    HMODULE hModule = $DLogGetNtdll();

    DBGPRINTF("Loading functions...\n");

    PIMAGE_OPTIONAL_HEADER  OptionalHeader  = (PIMAGE_OPTIONAL_HEADER )((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew + sizeof(ULONG) + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_DATA_DIRECTORY   DataDirectory   = (PIMAGE_DATA_DIRECTORY  )(&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + DataDirectory->VirtualAddress);

    ULONG      dwProcInited = 0;
    ULONG_PTR  dwExportBase = (ULONG_PTR)ExportDirectory;
    ULONG_PTR  dwExportEnd  = (ULONG_PTR)ExportDirectory + DataDirectory->Size;
    PULONG     dwFunctions  = (PULONG  )((ULONG_PTR)hModule + ExportDirectory->AddressOfFunctions);
    PULONG     dwNames      = (PULONG  )((ULONG_PTR)hModule + ExportDirectory->AddressOfNames);
    PUSHORT    nOrdinals    = (PUSHORT )((ULONG_PTR)hModule + ExportDirectory->AddressOfNameOrdinals);
    PULONG_PTR dwOurProc    = (PVOID   )&fnNtReadFile;
    ULONG      dwOutProcGot = 0;

    for (ULONG i = 0; i != ExportDirectory->NumberOfNames && dwProcInited != 7; i++) {
        ULONG_PTR dwFunctionAddress = (ULONG_PTR)hModule + dwFunctions[nOrdinals[i]];

        /* Not present in module */
        if (dwFunctionAddress < dwExportBase && dwFunctionAddress > dwExportEnd) {
            continue;
        }

        PSTR szName = (PSTR)((ULONG_PTR)hModule + dwNames[i]);

        for (ULONG y = 0; y != ARRAYSIZE(szFunctions); y++) {
            if ($RtlpCompareStringZ(szFunctions[y], szName)) {
                DBGPRINTF("\t0x%p = 0x%p \xB3 %s\n", &dwOurProc[y], dwFunctionAddress, szFunctions[y]);
                dwOurProc[y] = dwFunctionAddress;
                dwOutProcGot++;

                break;
            }
        }
    }

    if (dwOutProcGot != ARRAYSIZE(szFunctions)) {
        DBGPRINTF("\tFailed to load some functions!\n");

        for (ULONG i = 0; i != ARRAYSIZE(szFunctions); i++) {
            if (IS_NULL(dwOurProc[i])) {
                DBGPRINTF("\tMissing %s\n", szFunctions[i]);
            }
        }

        ERROREXIT(ERRORCODE_NOT_ALL_PROC_FOUND);
    }
}

typedef struct _DLOGINSTANCE {
    PVOID     pBuffer;
    HANDLE    hPipe;
    ULONG     dwStartedTick;
} DLOGINSTANCE, *PDLOGINSTANCE;

static CONST DWORD DLogTypesChars[DLG_FILTER_COUNT] = {
    0x20B32020, // DLOGTYPE_DEFAULT
    0x20B32A20, // DLOGTYPE_INFO
    0x20B32120, // DLOGTYPE_WARNING
    0x20B37820, // DLOGTYPE_ERROR
    0x20B37F20, // DLOGTYPE_CRITICAL
    0x20B32B20, // DLOGTYPE_SUCCESS
    0x20B3AF20  // DLOGTYPE_HIGHLIGHT
};

static CONST WCHAR DLogTypesColours[DLG_FILTER_COUNT] = {
    0x07FF, // DLOGTYPE_DEFAULT
    0x0FFF, // DLOGTYPE_INFO
    0x0EFF, // DLOGTYPE_WARNING
    0x0CFF, // DLOGTYPE_ERROR
    0x4FFF, // DLOGTYPE_CRITICAL
    0x0AFF, // DLOGTYPE_SUCCESS
    0xB0FF  // DLOGTYPE_HIGHLIGHT
};

static CONST CHAR AsciiHex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static DLOGINSTANCE GlobalDlogInstance;

static
VOID
FORCEINLINE
$HexToString(
    OUT PVOID  Destination,
    IN  PVOID  Source,
    IN  SIZE_T BytesCount
    )
{
    PBYTE sHex = (PVOID)((ULONG_PTR)&Source + BytesCount);

    BytesCount *= 2;

    #pragma unroll
    for (ULONG_PTR i = 0; i != BytesCount; i += 2) {
        sHex--;
        ((PBYTE)Destination)[i + 0] = AsciiHex[*sHex >> 4];
        ((PBYTE)Destination)[i + 1] = AsciiHex[*sHex & 0xF];
    }
}

#define UINT32_CHARS_MAX 9 // 4294967295

static
SIZE_T
FORCEINLINE
$DecimalToString(
    OUT PVOID  Destiantion,
    IN  ULONG  dwNumber,
    IN  SIZE_T MaxAlign
    )
{
    CHAR sBuffer[UINT32_CHARS_MAX + 1];
    ULONG cbBuffer = UINT32_CHARS_MAX;

    if (dwNumber) {
        while (dwNumber) {
            sBuffer[cbBuffer--] = AsciiHex[dwNumber % 10];
            dwNumber /= 10;
        }
    } else {
        sBuffer[cbBuffer--] = '0';
    }

    if (cbBuffer) {
        __stosb((PVOID)sBuffer , ' ', cbBuffer + 1);
    }

    __movsb(Destiantion, (PBYTE)sBuffer + (UINT32_CHARS_MAX - MaxAlign + 1), UINT32_CHARS_MAX + 1);

    return MaxAlign;
}

VOID
DLOGAPIX
$DLogSendExLocal(
    IN $DLOGTYPE Type,
    IN PSTR      szFunctioName,
    IN PCSTR     szFormat,
    IN ...
    )
{
    ULONG dwReserved;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    PDLOGINSTANCE DlogInstance = (PVOID)&$RtlpGetTeb()->TlsSlots[CFG_TLS_INDEX];
    PSTR szBuffer = (PVOID)DlogInstance->pBuffer;

    if (Type & DLG_ATT_COLOURS) {
        *((PWCHAR)szBuffer)++ = DLogTypesColours[Type & 0xFFFF];
    }

    if (Type & DLG_ATT_TICKS) {
        szBuffer += $DecimalToString(szBuffer, $RtlpGetTickCount() - DlogInstance->dwStartedTick, UINT32_CHARS_MAX);
        *szBuffer++ = ' ';
    }
    
    if (Type & DLG_ATT_PID) {
        szBuffer += $DecimalToString(szBuffer, (ULONG)$RtlpGetTeb()->ClientId.UniqueProcess, 4);
        *szBuffer++ = (Type & DLG_ATT_TID) ? ':' : ' ';
    }

    if (Type & DLG_ATT_TID) {
        szBuffer += $DecimalToString(szBuffer, (ULONG)$RtlpGetTeb()->ClientId.UniqueThread, 4);
        *szBuffer++ = ' ';
    }

    if (Type & DLG_ATT_ADDRESS) {
        #ifdef _AMD64_
            szBuffer[ 0] = '0';
            szBuffer[ 1] = 'x';
            $HexToString(szBuffer + 2, _AddressOfReturnAddress(), sizeof(ULONG_PTR));
            szBuffer[18] = ' ';
        #else
            szBuffer[ 0] = '0';
            szBuffer[ 1] = 'x';
            $HexToString(szBuffer + 2, _AddressOfReturnAddress(), sizeof(ULONG_PTR));
            szBuffer[10] = ' ';
        #endif

        szBuffer += sizeof(ULONG_PTR) * 2 + 3;
    }

    if (Type & DLG_ATT_PROCNAME) {
        ULONG dwEndAlignment = Type >> 24;
        ULONG cbFunctionName = 0;
        
        while (*szFunctioName) {
            *szBuffer++ = *szFunctioName++;
            cbFunctionName++;
        }

        if (cbFunctionName < dwEndAlignment) {
            dwEndAlignment -= cbFunctionName;

            for (ULONG i = 0; i != dwEndAlignment; i++) {
                *szBuffer++ = ' ';
            }
        }
    }

    *((PDWORD)szBuffer)++ = DLogTypesChars[Type & 0xFFFF];

    /* I know "CFG_CB_WRITE_BUFFER" is not the correct size, just eliminating error checking for speed */
    if (!(szBuffer += fnVsnprintf(szBuffer, CFG_CB_WRITE_BUFFER, szFormat, (PVOID)((PULONG_PTR)&szFormat + 1)))) {
        return;
    }

    if (!NT_SUCCESS(Status = fnNtWriteFile(DlogInstance->hPipe, NULL, NULL, NULL, &IoStatus, DlogInstance->pBuffer, (ULONG_PTR)szBuffer - (ULONG_PTR)DlogInstance->pBuffer, NULL, NULL))) {
        DBGPRINTF("\tNtWriteFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTWRITEFILE);
    }

    if (!NT_SUCCESS(Status = fnNtReadFile(DlogInstance->hPipe, NULL, NULL, NULL, &IoStatus, &dwReserved, CFG_CB_READ_BUFFER, NULL, NULL))) {
        DBGPRINTF("\tNtReadFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTREADFILE);
    }
}

VOID
DLOGAPIX
$DLogSendExGlobal(
    IN $DLOGTYPE Type,
    IN PSTR      szFunctioName,
    IN PCSTR     szFormat,
    IN ...
    )
{
    ULONG dwReserved;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    PDLOGINSTANCE DlogInstance = (PVOID)&$RtlpGetTeb()->TlsSlots[CFG_TLS_INDEX];
    PSTR szBuffer = (PVOID)GlobalDlogInstance.pBuffer;

    if (Type & DLG_ATT_COLOURS) {
        *((PWCHAR)szBuffer)++ = DLogTypesColours[Type & 0xFFFF];
    }

    if (Type & DLG_ATT_TICKS) {
        szBuffer += $DecimalToString(szBuffer, $RtlpGetTickCount() - GlobalDlogInstance.dwStartedTick, UINT32_CHARS_MAX);
        *szBuffer++ = ' ';
    }
    
    if (Type & DLG_ATT_PID) {
        szBuffer += $DecimalToString(szBuffer, (ULONG)$RtlpGetTeb()->ClientId.UniqueProcess, 4);
        *szBuffer++ = (Type & DLG_ATT_TID) ? ':' : ' ';
    }

    if (Type & DLG_ATT_TID) {
        szBuffer += $DecimalToString(szBuffer, (ULONG)$RtlpGetTeb()->ClientId.UniqueThread, 4);
        *szBuffer++ = ' ';
    }

    if (Type & DLG_ATT_ADDRESS) {
        #ifdef _AMD64_
            szBuffer[ 0] = '0';
            szBuffer[ 1] = 'x';
            $HexToString(szBuffer + 2, _AddressOfReturnAddress(), sizeof(ULONG_PTR));
            szBuffer[18] = ' ';
        #else
            szBuffer[ 0] = '0';
            szBuffer[ 1] = 'x';
            $HexToString(szBuffer + 2, _AddressOfReturnAddress(), sizeof(ULONG_PTR));
            szBuffer[10] = ' ';
        #endif

        szBuffer += sizeof(ULONG_PTR) * 2 + 3;
    }

    if (Type & DLG_ATT_PROCNAME) {
        ULONG dwEndAlignment = Type >> 24;
        ULONG cbFunctionName = 0;
        
        while (*szFunctioName) {
            *szBuffer++ = *szFunctioName++;
            cbFunctionName++;
        }

        if (cbFunctionName < dwEndAlignment) {
            dwEndAlignment -= cbFunctionName;

            for (ULONG i = 0; i != dwEndAlignment; i++) {
                *szBuffer++ = ' ';
            }
        }
    }

    *((PDWORD)szBuffer)++ = DLogTypesChars[Type & 0xFFFF];

    /* I know "CFG_CB_WRITE_BUFFER" is not the correct size, just eliminating error checking for speed */
    if (!(szBuffer += fnVsnprintf(szBuffer, CFG_CB_WRITE_BUFFER, szFormat, (PVOID)((PULONG_PTR)&szFormat + 1)))) {
        return;
    }

    if (!NT_SUCCESS(Status = fnNtWriteFile(GlobalDlogInstance.hPipe, NULL, NULL, NULL, &IoStatus, GlobalDlogInstance.pBuffer, (ULONG_PTR)szBuffer - (ULONG_PTR)GlobalDlogInstance.pBuffer, NULL, NULL))) {
        DBGPRINTF("\tNtWriteFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTWRITEFILE);
    }

    if (!NT_SUCCESS(Status = fnNtReadFile(GlobalDlogInstance.hPipe, NULL, NULL, NULL, &IoStatus, &dwReserved, CFG_CB_READ_BUFFER, NULL, NULL))) {
        DBGPRINTF("\tNtReadFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTREADFILE);
    }
}

VOID
DLOGAPIX
$DLogSendLocal(
    IN PCSTR szFormat,
    IN ...
    )
{
    ULONG dwReserved;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    PDLOGINSTANCE DlogInstance = (PVOID)&$RtlpGetTeb()->TlsSlots[CFG_TLS_INDEX];
    ULONG_PTR cbMessage = fnVsnprintf(DlogInstance->pBuffer, CFG_CB_WRITE_BUFFER, szFormat, (PVOID)((PULONG_PTR)&szFormat + 1));

    if (!cbMessage) {
        return;
    }

    if (!NT_SUCCESS(Status = fnNtWriteFile(DlogInstance->hPipe, NULL, NULL, NULL, &IoStatus, DlogInstance->pBuffer, cbMessage, NULL, NULL))) {
        DBGPRINTF("\tNtWriteFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTWRITEFILE);
    }

    if (!NT_SUCCESS(Status = fnNtReadFile(DlogInstance->hPipe, NULL, NULL, NULL, &IoStatus, &dwReserved, CFG_CB_READ_BUFFER, NULL, NULL))) {
        DBGPRINTF("\tNtReadFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTREADFILE);
    }
}

VOID
DLOGAPIX
$DLogSendGlobal(
    IN PCSTR szFormat,
    IN ...
    )
{
    ULONG dwReserved;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    ULONG_PTR cbMessage = fnVsnprintf(GlobalDlogInstance.pBuffer, CFG_CB_WRITE_BUFFER, szFormat, (PVOID)((PULONG_PTR)&szFormat + 1));

    if (!cbMessage) {
        return;
    }

    if (!NT_SUCCESS(Status = fnNtWriteFile(GlobalDlogInstance.hPipe, NULL, NULL, NULL, &IoStatus, GlobalDlogInstance.pBuffer, cbMessage, NULL, NULL))) {
        DBGPRINTF("\tNtWriteFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTWRITEFILE);
    }

    if (!NT_SUCCESS(Status = fnNtReadFile(GlobalDlogInstance.hPipe, NULL, NULL, NULL, &IoStatus, &dwReserved, CFG_CB_READ_BUFFER, NULL, NULL))) {
        DBGPRINTF("\tNtReadFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTREADFILE);
    }
}

VOID
DLOGAPI
$DLogDestroy(
    IN BOOL bDestroyLocal
    )
{
    DBGPRINTF("Destroying current instance\n");

    PDLOGINSTANCE DlogInstance = bDestroyLocal ? (PVOID)&$RtlpGetTeb()->TlsSlots[CFG_TLS_INDEX] : &GlobalDlogInstance;

    /* Check if we are allready inited for this thread */
    if (IS_NULL(DlogInstance->pBuffer) && !CFG_CB_WRITE_BUFFER && IS_NULL(DlogInstance->hPipe)) {
        DBGPRINTF("\tThis thread is not initialized\n");

        return;
    }

    NTSTATUS Status;
    SIZE_T stUnused = 0;

    if (!NT_SUCCESS(Status = fnNtFreeVirtualMemory(NtCurrentProcess(), &DlogInstance->pBuffer, &stUnused, MEM_RELEASE))) {
        DBGPRINTF("\tNtFreeVirtualMemory failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTFREEVIRTUALMEMORY);
    }

    if (!NT_SUCCESS(Status = fnNtClose(DlogInstance->hPipe))) {
        DBGPRINTF("\tNtClose failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTCLOSE);
    }
}

VOID
DLOGAPI
$DLogInitialize(
    IN PUNICODE_STRING MasterPipeName,
    IN BOOL bCreateLocal
    )
{
    if (!bFunctionsInited) {
        $DLogInitializeFunctions();
    }

    DBGPRINTF("Connecting to %ls\n", MasterPipeName->Buffer);

    PDLOGINSTANCE DlogInstance = bCreateLocal ? (PVOID)&$RtlpGetTeb()->TlsSlots[CFG_TLS_INDEX] : &GlobalDlogInstance;

    /* Check if we are allready inited for this thread */
    if (NOT_NULL(DlogInstance->pBuffer) && CFG_CB_WRITE_BUFFER && NOT_INVALID_HANDLE(DlogInstance->hPipe)) {
        DBGPRINTF("\tThis thread was already initialized\n");

        return;
    }

    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES Object;
	SIZE_T stWriteBufferSize = CFG_CB_WRITE_BUFFER;

    InitializeObjectAttributes(
        &Object,
        MasterPipeName,
        0,
        NULL,
        NULL
    );

    DlogInstance->dwStartedTick = $RtlpGetTickCount();
	
    if (!NT_SUCCESS(Status = fnNtAllocateVirtualMemory(NtCurrentProcess(), &DlogInstance->pBuffer, 0, &stWriteBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        DBGPRINTF("\tNtAllocateVirtualMemory failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTALLOCATEVIRTUALMEMORY);
    }
	
    if (!NT_SUCCESS(Status = fnNtCreateFile(&DlogInstance->hPipe, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &Object, &IoStatus, NULL, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0))) {
        DBGPRINTF("\tNtCreateFile failed! 0x%08lX\n", Status);
        ERROREXIT(ERRORCODE_NTCREATEFILE);
    }

    DBGPRINTF(
        "\tAddress of buffer = 0x%p (%lu Bytes)\n"
        "\tAddress of pipe   = 0x%p\n"
        "\tStarted tick      = %lu\n",
        DlogInstance->pBuffer, CFG_CB_WRITE_BUFFER,
        DlogInstance->hPipe,
        DlogInstance->dwStartedTick
    );
}

#ifdef DEBUG
    int
    main()
    {
        UNICODE_STRING PipeName = CONST_UNICODE_STRING(L"\\??\\pipe\\{6F9A9D97-3E66-767D-4C3C-C09739483C20}");

        $DLogInitialize(&PipeName, FALSE);

        for (ULONG i = 0; i != DLG_FILTER_COUNT; i++) {
            $DLogSendExGlobal(
                ($DLOGTYPE)(
                    i | DLG_ATT_COLOURS | DLG_ATT_PID | DLG_ATT_TID | DLG_ATT_TICKS | DLG_ATT_ADDRESS | DLG_ATT_PROCNAME | DLG_ATT_PROCNAME_ALIGN(20)
                ),
                __PRETTY_FUNCTION__,
                "Intel(R) C++ Intel(R) 64 Compiler for applications running on IA-32, Version 19.0.2.190 Build 20190117"
            );
        }

        $DLogDestroy(FALSE);

        return 0;
    }
#endif
