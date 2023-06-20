#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include <intrin.h>
#include "encryption.hpp"

extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS * Process);
extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);

extern "C" NTSYSCALLAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
inline ULONG NtBuildNumber;