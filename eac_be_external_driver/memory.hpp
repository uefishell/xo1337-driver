#pragma once

#define RVA(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))
#define PRINT(fmt, ...) DbgPrintEx(0, 0, skCrypt("[RAGE] " fmt), __VA_ARGS__)

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	unsigned int Length;
	int Initialized;
	void* SSHandle;
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	// ...
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB64
{
	unsigned char InheritedAddressSpace;	// 0x0000 
	unsigned char ReadImageFileExecOptions;	// 0x0001 
	unsigned char BeingDebugged;			// 0x0002 
	unsigned char BitField;					// 0x0003 
	unsigned char pad_0x0004[0x4];			// 0x0004
	PVOID Mutant;							// 0x0008 
	PVOID ImageBaseAddress;					// 0x0010 
	PPEB_LDR_DATA Ldr;						// 0x0018
	// ...
} PEB64, * PPEB64;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_MODULE {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	SystemSupportedProcessArchitectures = 0xb5,
} SYSTEM_INFORMATION_CLASS;

typedef struct _KTHREAD_FLAGS
{
	union
	{
		struct
		{
			ULONG AutoBoostActive : 1;                                        //0x74
			ULONG ReadyTransition : 1;                                        //0x74
			ULONG WaitNext : 1;                                               //0x74
			ULONG SystemAffinityActive : 1;                                   //0x74
			ULONG Alertable : 1;                                              //0x74
			ULONG UserStackWalkActive : 1;                                    //0x74
			ULONG ApcInterruptRequest : 1;                                    //0x74
			ULONG QuantumEndMigrate : 1;                                      //0x74
			ULONG UmsDirectedSwitchEnable : 1;                                //0x74
			ULONG TimerActive : 1;                                            //0x74
			ULONG SystemThread : 1;                                           //0x74
			ULONG ProcessDetachActive : 1;                                    //0x74
			ULONG CalloutActive : 1;                                          //0x74
			ULONG ScbReadyQueue : 1;                                          //0x74
			ULONG ApcQueueable : 1;                                           //0x74
			ULONG ReservedStackInUse : 1;                                     //0x74
			ULONG UmsPerformingSyscall : 1;                                   //0x74
			ULONG TimerSuspended : 1;                                         //0x74
			ULONG SuspendedWaitMode : 1;                                      //0x74
			ULONG SuspendSchedulerApcWait : 1;                                //0x74
			ULONG CetUserShadowStack : 1;                                     //0x74
			ULONG BypassProcessFreeze : 1;                                    //0x74
			ULONG Reserved : 10;                                              //0x74
		} BitFields;
		LONG MiscFlags;                                                     //0x74
	} Internal;
};


namespace imports
{
	typedef struct _HANDLE_TABLE_ENTRY_INFO
	{
		ULONG AuditMask;
	} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

	typedef struct _HANDLE_TABLE_ENTRY
	{
		union
		{
			PVOID Object;
			ULONG_PTR ObAttributes;
			PHANDLE_TABLE_ENTRY_INFO InfoTable;
			ULONG_PTR Value;
		};
		union
		{
			ULONG GrantedAccess;
			struct
			{
				USHORT GrantedAccessIndex;
				USHORT CreatorBackTraceIndex;
			};
			LONG NextFreeTableEntry;
		};
	} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

	size_t strlen(const char* String)
	{
		UINT32 Length = 0;

		while (*String)
		{
			Length++;
			String++;
		}

		return (Length);
	}

	int __cdecl memcmp(const void* s1, const void* s2, size_t n)
	{
		if (n != 0) {
			const unsigned char* p1 = (const unsigned char*)s1, * p2 = (const unsigned char*)s2;
			do {
				if (*p1++ != *p2++)
					return (*--p1 - *--p2);
			} while (--n != 0);
		}
		return 0;
	}

	int strcmp(const char* String1, const char* String2)
	{
		for (; (*String1 == *String2); String2++)
		{
			if (!*String1++)
			{
				return (0);
			}
		}

		return ((unsigned char)*String1 - (unsigned char)*String2);
	}

	NTSTATUS ZwQuerySystemInformation_impl(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
	{
		return ZwQuerySystemInformation(InfoClass, Buffer, Length, ReturnLength);
	}

	PVOID ExAllocatePool_impl(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
	{
		return ExAllocatePool(PoolType, NumberOfBytes);
	}

	void ExFreePoolWithTag_impl(PVOID P, ULONG Tag)
	{
		ExFreePoolWithTag(P, Tag);
	}
}

namespace memory
{
	inline bool is_valid_process(HANDLE pid)
	{
		if (!pid)
			return false;

		PEPROCESS process;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
			return false;

		return true;
	}

	inline PIMAGE_NT_HEADERS get_nt_headers(PVOID module) 
	{
		if (!module)
			return nullptr;

		return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
	}

	inline PBYTE find_pattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) 
	{
		if (!module)
			return nullptr;

		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++) {
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

		for (auto x = 0; x < size - imports::strlen(mask); x++) {

			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask)) {
				return addr;
			}
		}

		return NULL;
	}

	inline PBYTE find_pattern(PVOID base, LPCSTR pattern, LPCSTR mask) 
	{
		if (!base) return 0;

		auto header = get_nt_headers(base);
		auto section = IMAGE_FIRST_SECTION(header);

		for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {

			if (!imports::memcmp(section->Name, skCrypt(".text"), 5) || !imports::memcmp(section->Name, skCrypt("PAGE"), 4)) 
			{
				auto addr = find_pattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (addr) 
					return addr;			
			}
		}

		return NULL;
	}

	inline PVOID get_system_base(const CHAR* system_module) 
	{
		PVOID addr = 0;
		ULONG size = 0;

		NTSTATUS status = imports::ZwQuerySystemInformation_impl(SystemModuleInformation, 0, 0, &size);
		if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

		PSYSTEM_MODULE_INFORMATION modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(imports::ExAllocatePool_impl(NonPagedPool, size));
		if (!modules) return 0;

		if (!NT_SUCCESS(status = imports::ZwQuerySystemInformation_impl(SystemModuleInformation, modules, size, 0)))
		{
			imports::ExFreePoolWithTag_impl(modules, 0);
			return 0;
		}

		for (int i = 0; i < modules->NumberOfModules; i++)
		{
			if (imports::strcmp((CHAR*)modules->Modules[i].FullPathName, system_module) == 0)
			{
				addr = modules->Modules[i].ImageBase;
				break;
			}
		}

		imports::ExFreePoolWithTag_impl(modules, 0);
		return addr;
	}

	inline ULONG_PTR get_process_cr3(PEPROCESS pProcess)
	{
		if (!pProcess)
			return 0;

		PUCHAR process = (PUCHAR)pProcess;
		ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
		if (process_dirbase == 0)
		{
			ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + kernel_KPROCESS::UserDirectoryTableBase);
			return process_userdirbase;
		}
		return process_dirbase;
	}

	inline ULONG_PTR get_kernel_dir_base()
	{
		PUCHAR process = (PUCHAR)IoGetCurrentProcess();
		if (!process) return 0;

		ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
		return cr3;
	}

	inline NTSTATUS read_phys_addr(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
	{
		if (!TargetAddress || !lpBuffer || Size <= 0)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS AddrToRead = { 0 };
		AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
		return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
	}

	inline NTSTATUS write_phys_addr(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
	{
		if (!TargetAddress || !lpBuffer || Size <= 0)
			return STATUS_UNSUCCESSFUL;

		PHYSICAL_ADDRESS AddrToWrite = { 0 };
		AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

		PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

		if (!pmapped_mem)
			return STATUS_UNSUCCESSFUL;

		memcpy(pmapped_mem, lpBuffer, Size);

		if (BytesWritten)
			*BytesWritten = Size;
		
		MmUnmapIoSpace(pmapped_mem, Size);
		return STATUS_SUCCESS;
	}

	#define PAGE_OFFSET_SIZE 12
	static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

	inline UINT64 translate_linear_address(UINT64 directoryTableBase, UINT64 virtualAddress)
	{
		if (!directoryTableBase || !virtualAddress)
			return 0;
		directoryTableBase &= ~0xf;

		UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
		UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
		UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
		UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
		UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

		SIZE_T readsize = 0;
		UINT64 pdpe = 0;
		read_phys_addr((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
		if (~pdpe & 1)
			return 0;

		UINT64 pde = 0;
		read_phys_addr((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
		if (~pde & 1)
			return 0;

		/* 1GB large page, use pde's 12-34 bits */
		if (pde & 0x80)
			return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

		UINT64 pteAddr = 0;
		read_phys_addr((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
		if (~pteAddr & 1)
			return 0;

		/* 2MB large page */
		if (pteAddr & 0x80)
			return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

		virtualAddress = 0;
		read_phys_addr((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
		virtualAddress &= PMASK;

		if (!virtualAddress)
			return 0;

		return virtualAddress + pageOffset;
	}

	inline NTSTATUS read_phys_memory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read = nullptr)
	{
		PEPROCESS pProcess = NULL;
		if (!pid || !Address || !AllocatedBuffer || size <= 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = get_process_cr3(pProcess);
		ObfDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			UINT64 CurPhysAddr = translate_linear_address(process_dirbase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			NtRet = read_phys_addr((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesRead == 0) break;
		}

		if (read != nullptr)
			*read = CurOffset;

		return NtRet;
	}

	inline NTSTATUS write_phys_memory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written = nullptr)
	{
		PEPROCESS pProcess = NULL;
		if (!pid || !Address || !AllocatedBuffer || size <= 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = get_process_cr3(pProcess);
		ObfDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			UINT64 CurPhysAddr = translate_linear_address(process_dirbase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			NtRet = write_phys_addr((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesWritten == 0) break;
		}

		if (written != nullptr)
			*written = CurOffset;
		return NtRet;
	}

	inline PVOID get_process_base_ud(HANDLE pid)
	{
		PEPROCESS process = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return 0;
		
		return reinterpret_cast<PVOID>(PsGetProcessSectionBaseAddress(process));
	}

	inline bool spoof_thread(PVOID process_id, ULONG64 thread_id, BOOLEAN enable)
	{
		if ((ULONG64)process_id <= 0 || thread_id <= 0)
			return false;

		PEPROCESS source_process;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(process_id, &source_process)))
			return false;

		_KTHREAD *thread;

		NTSTATUS status = PsLookupThreadByThreadId((HANDLE)thread_id, &thread);
		if (status != STATUS_SUCCESS) 
			return false;

		PEPROCESS thread_process = PsGetThreadProcess(thread);
		if (!thread_process)
			return false;

		if (source_process != thread_process)
			return false;

		// _KTHREAD.Process = struct _KPROCESS* Process; //0x220

		_KTHREAD_FLAGS* miscFlags = (_KTHREAD_FLAGS*)((char*)thread + 0x74);
		if (miscFlags)
		{
			miscFlags->Internal.BitFields.ApcQueueable = (enable ? 1 : 0);
		}
			

		return true;
	}
}


/*inline PVOID get_module_base_x64(HANDLE pid, LPCWSTR module_name)
{
	if (!pid || !module_name) return 0;

	PEPROCESS process = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return 0;

	PVOID result = 0;

	PVOID buf = ExAllocatePool(NonPagedPool, wcslen(module_name) * sizeof(wchar_t) + 1);
	if (!buf) return 0;

	memcpy(buf, module_name, wcslen(module_name) * sizeof(wchar_t) + 1);

	UNICODE_STRING moduleName;
	RtlInitUnicodeString(&moduleName, (PCWSTR)buf);

	PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
	if (!peb) return 0;

	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	for (PLIST_ENTRY pListEntry = peb->Ldr->InLoadOrderLinks.Flink; pListEntry != &peb->Ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		if (!pListEntry)
			continue;

		PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&module_entry->BaseDllName, &moduleName, TRUE) == 0)
			result = module_entry->DllBase;
	}

	KeUnstackDetachProcess(&state);
	if (buf)
		ExFreePoolWithTag(buf, 0);

	return result;
}*/