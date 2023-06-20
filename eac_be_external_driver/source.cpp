#include "includes.hpp"

#include "structures.hpp"

#include "offsets.hpp"

#include "memory.hpp"

__int64(__fastcall* NtDCompositionRegisterThumbnailVisual_orig)(
	__int64 a1,
	__int64 a2,
	__int64 a3,
	unsigned int a4,
	__int64 a5,
	__int64 a6,
	char a7,
	__int64 a8,
	__int64 a9);

__int64 __fastcall NtDCompositionRegisterThumbnailVisual_hook(
	__int64 a1,
	__int64 a2,
	__int64 a3,
	unsigned int a4,
	__int64 a5,
	__int64 a6,
	char a7,
	__int64 a8,
	__int64 a9) {

	if (ExGetPreviousMode() != UserMode)
		return NtDCompositionRegisterThumbnailVisual_orig(a1, a2, a3, a4, a5, a6, a7, a8, a9);

	if (a1 == 0x1337 && a2 == 0x1337 && a3 == 0x1337 && a4 == 0x1337 && a5 == 0x1337 && a6 == 0x1337)
	{
		ke::KERNEL_REQUEST* vm_guest_ctx = (ke::KERNEL_REQUEST*)a8;
		if (!vm_guest_ctx)
			return NtDCompositionRegisterThumbnailVisual_orig(a1, a2, a3, a4, a5, a6, a7, a8, a9);

		if (vm_guest_ctx->magic != KE_MAGIC)
			return NtDCompositionRegisterThumbnailVisual_orig(a1, a2, a3, a4, a5, a6, a7, a8, a9);

		char* current_thread = (char*)KeGetCurrentThread();
		if (current_thread)
			*reinterpret_cast<ULONG*>(current_thread + 0x80) = 0; // hide syscall id from last thread caller

		NTSTATUS request_status = STATUS_SUCCESS;

		if (vm_guest_ctx->id == ke::KERNEL_ID_WRITE)
		{
			if (vm_guest_ctx->pid && vm_guest_ctx->dst && vm_guest_ctx->out && vm_guest_ctx->size > 0)
			{
				if (memory::is_valid_process(vm_guest_ctx->pid))
				{
					request_status = memory::write_phys_memory(vm_guest_ctx->pid, vm_guest_ctx->dst, vm_guest_ctx->out, vm_guest_ctx->size);
				}
			}
		}
		else if (vm_guest_ctx->id == ke::KERNEL_ID_READ)
		{
			if (vm_guest_ctx->pid && vm_guest_ctx->dst && vm_guest_ctx->out && vm_guest_ctx->size > 0)
			{
				if (memory::is_valid_process(vm_guest_ctx->pid))
				{
					request_status = memory::read_phys_memory(vm_guest_ctx->pid, vm_guest_ctx->dst, vm_guest_ctx->out, vm_guest_ctx->size);
				}
			}
		}
		/*else if (vm_guest_ctx->id == ke::KERNEL_ID_MODULE)
		{
			if (vm_guest_ctx->pid)
			{
				if (memory::is_valid_process(vm_guest_ctx->pid))
				{
					vm_guest_ctx->out = memory::get_module_base_x64(vm_guest_ctx->pid, vm_guest_ctx->name);
				}
			}
		}*/
		else if (vm_guest_ctx->id == ke::KERNEL_ID_GET_PROCESS_EXE_BASE)
		{
			if (vm_guest_ctx->pid)
			{
				if (memory::is_valid_process(vm_guest_ctx->pid))
				{
					vm_guest_ctx->out = memory::get_process_base_ud(vm_guest_ctx->pid);
				}
			}
		}
		else if (vm_guest_ctx->id == ke::KERNEL_ID_RUNNING)
		{
			vm_guest_ctx->out = reinterpret_cast<PVOID>(0x2000);
		}
		else
		{
			request_status = STATUS_UNSUCCESSFUL;
		}

		*reinterpret_cast<NTSTATUS*>(a9) = request_status;

		return 0;
	}

	return NtDCompositionRegisterThumbnailVisual_orig(a1, a2, a3, a4, a5, a6, a7, a8, a9);
}

NTSTATUS Main()
{
	PVOID base = memory::get_system_base(skCrypt("\\SystemRoot\\System32\\win32k.sys"));
	if (!base) return STATUS_ACCESS_VIOLATION;

	PVOID sig = memory::find_pattern(
		base,
		skCrypt("\x48\x8B\x05\x00\x00\x00\x00\x45\x8B\xD9\x48\x8B\xDA\x48\x8B\xF9\x48\x85\xC0\x74\x00\x44\x8A\x8C\x24"),
		skCrypt("xxx????xxxxxxxxxxxxx?xxxx")
	);
	if (!sig) return STATUS_ACCESS_VIOLATION;

	sig = RVA(sig, 7);
	if (!sig) return STATUS_ACCESS_VIOLATION;

	*(PVOID*)&NtDCompositionRegisterThumbnailVisual_orig = _InterlockedExchangePointer(
		(volatile PVOID*)sig,
		&NtDCompositionRegisterThumbnailVisual_hook
	);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING unicode_string)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(unicode_string);

	NTSTATUS Status = Main();
	return Status;
}
