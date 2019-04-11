#include "dlog.h"

NTSTATUS
(NTAPI * fnNtReadFile)(
    IN  HANDLE           FileHandle,
    IO  HANDLE           Event,
    IO  PIO_APC_ROUTINE  ApcRoutine,
    IO  PVOID            ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID            Buffer,
    IN  ULONG            Length,
    IO  PLARGE_INTEGER   ByteOffset,
    IO  PULONG           Key
    ) = NULL;

NTSTATUS
(NTAPI * fnNtWriteFile)(
    IN  HANDLE           FileHandle,
    IO  HANDLE           Event,
    IO  PIO_APC_ROUTINE  ApcRoutine,
    IO  PVOID            ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID            Buffer,
    IN  ULONG            Length,
    IO  PLARGE_INTEGER   ByteOffset,
    IO  PULONG           Key
    ) = NULL;

NTSTATUS
(NTAPI * fnNtCreateFile)(
    OUT PHANDLE            FileHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK   IoStatusBlock,
    IN  PLARGE_INTEGER     AllocationSize,
    IN  ULONG              FileAttributes,
    IN  ULONG              ShareAccess,
    IN  ULONG              CreateDisposition,
    IN  ULONG              CreateOptions,
    IN  PVOID              EaBuffer,
    IN  ULONG              EaLength
    ) = NULL;

NTSTATUS
(NTAPI * fnNtFreeVirtualMemory)(
    IN HANDLE  ProcessHandle,
    IO PVOID  *BaseAddress,
    IO PSIZE_T RegionSize,
    IN ULONG   FreeType
    ) = NULL;

NTSTATUS
(NTAPI * fnNtAllocateVirtualMemory)(
    IN HANDLE    ProcessHandle,
    IO PVOID    *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IO PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    ) = NULL;

NTSTATUS
(NTAPI * fnNtClose)(
    IN HANDLE Handle
    ) = NULL;

INT
(CDECL * fnVsnprintf)(
    OUT PVOID pBuffer,
    IN  SIZE_T BufferMax,
    IN  PCSTR  szFormat,
    IN  PVOID  VaArgs
    ) = NULL;
