#ifndef _NTAPI_H
#define _NTAPI_H

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)

extern
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
    );

extern
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
    );

extern
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
    );

extern
NTSTATUS
(NTAPI * fnNtFreeVirtualMemory)(
    IN HANDLE  ProcessHandle,
    IO PVOID  *BaseAddress,
    IO PSIZE_T RegionSize,
    IN ULONG   FreeType
    );

extern
NTSTATUS
(NTAPI * fnNtAllocateVirtualMemory)(
    IN HANDLE    ProcessHandle,
    IO PVOID    *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IO PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    );

extern
NTSTATUS
(NTAPI * fnNtClose)(
    IN HANDLE Handle
    );

extern
INT
(CDECL * fnVsnprintf)(
    OUT PVOID  pBuffer,
    IN  SIZE_T BufferMax,
    IN  PCSTR  szFormat,
    IN  PVOID  VaArgs
    );

#endif
