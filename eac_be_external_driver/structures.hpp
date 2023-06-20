#pragma once

#define KE_MAGIC 0x4040

namespace ke
{
	enum : UINT32
	{
		KERNEL_ID_WRITE,
		KERNEL_ID_READ,
		KERNEL_ID_MODULE,
		KERNEL_ID_GET_PROCESS_EXE_BASE,
		KERNEL_ID_RUNNING,
		KERNEL_ID_SPOOF_THREAD
	};

	typedef struct _KERNEL_REQUEST
	{
		UINT32 magic; // 0x4040
		UINT32 id;
		PVOID pid;
		PVOID dst;
		PVOID out;
		ULONGLONG size;
		BOOLEAN physhical;
		LPCWSTR name;
	} KERNEL_REQUEST, * PKERNEL_REQUEST;
}