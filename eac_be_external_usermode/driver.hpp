#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>

namespace driver {

	inline constexpr auto ke_magic = 0x4040;

	enum : UINT32
	{
		kernel_id_write = 0U,
		kernel_id_read = 1U,
		kernel_id_module = 2U,
		kernel_id_get_process_exe_base = 3U,
		kernel_id_running = 4U,
		kernel_id_spoof_thread = 5U
	};

	typedef struct _kernel_request
	{
		UINT32 magic; // 0x4040
		UINT32 id;
		PVOID pid;
		PVOID dst;
		PVOID out;
		ULONGLONG size;
		BOOLEAN physhical;
		LPCWSTR name;
	} kernel_request, * p_kernel_request;

	namespace detail {

		inline void* function;
		inline unsigned __int64 process_id;
		inline std::string process_name;
		inline ULONG64 process_base;
		inline IMAGE_DOS_HEADER dos_header;
		inline IMAGE_NT_HEADERS64 nt_headers;

		inline unsigned __int64 get_process_id(const char* process_name) {

			unsigned __int64 identifier = 0;

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!snapshot || snapshot == INVALID_HANDLE_VALUE)
				return 0;

			PROCESSENTRY32 pe32{ sizeof(PROCESSENTRY32) };
			if (Process32First(snapshot, &pe32))
				while (Process32Next(snapshot, &pe32))
					if (strcmp(pe32.szExeFile, process_name) == 0) {
						identifier = pe32.th32ProcessID;
						break;
					}

			CloseHandle(snapshot);
			return identifier;
		}

		template<typename T>
		bool send(T& args)
		{
			__int64(*usermode_caller)(__int64, __int64, __int64, unsigned int, __int64, __int64, char, void*, void*) = 0;
			usermode_caller = (decltype(usermode_caller))detail::function;

			NTSTATUS status;
			usermode_caller(0x1337, 0x1337, 0x1337, 0x1337, 0x1337, 0x1337, 0, &args, &status);
			return (status == 0ull);
		}
	}

	bool running();

	inline bool initialize(const std::string& process_name) 
	{
		LoadLibraryW(L"user32.dll");
		LoadLibraryW(L"win32u.dll");

		*(FARPROC*)&detail::function = GetProcAddress(GetModuleHandleW(L"win32u.dll"), "NtDCompositionRegisterThumbnailVisual");
		detail::process_id = 0;
		detail::process_name = process_name;
		detail::process_base = 0;

		return running();
	}

	bool running()
	{
		_kernel_request message;
		message.magic = ke_magic;
		message.id = kernel_id_running;

		detail::send(message);
		return (message.out == (PVOID)0x2000);
	}

	inline bool read_memory(void* address, void* buffer, uint64_t size)
	{
		if (!address || !buffer || size <= 0) return false;

		_kernel_request message;
		message.magic = ke_magic;
		message.id = kernel_id_read;
		message.pid = reinterpret_cast<PVOID>(detail::process_id);
		message.dst = address;
		message.out = buffer;
		message.size = size;
		message.physhical = FALSE;

		return detail::send(message);
	}

	inline bool write_memory(void* address, void* buffer, std::uint64_t size)
	{
		if (!address || !buffer || size <= 0) return false;

		_kernel_request message;
		message.magic = ke_magic;
		message.id = kernel_id_write;
		message.pid = reinterpret_cast<PVOID>(detail::process_id);
		message.dst = address;
		message.out = buffer;
		message.size = size;
		message.physhical = FALSE;

		return detail::send(message);
	}

	inline uint64_t get_base_address()
	{
		_kernel_request message;
		message.magic = ke_magic;
		message.id = kernel_id_get_process_exe_base;
		message.pid = reinterpret_cast<PVOID>(detail::process_id);

		return (detail::send(message) ? (uint64_t)message.out : 0);
	}

	template<typename T>
	inline T read(uint64_t address)
	{
		T buffer;
		bool result = read_memory((void*)address, &buffer, sizeof(buffer));
		return (result ? buffer : T());
	}

	template<typename T>
	inline bool write(uint64_t address, T value)
	{
		bool result = write_memory((void*)address, &value, sizeof(value));
		return result;
	}

	inline bool valid_address(uint64_t address)
	{
		return (address > 0 && address < INT64_MAX);
	}

	inline bool address_inside_process(uint64_t address)
	{
		return (address > 0 && address <= (detail::process_base + detail::nt_headers.OptionalHeader.SizeOfImage));
	}

	inline bool attach()
	{
		do
		{
			detail::process_id = detail::get_process_id(detail::process_name.c_str());
		} while (detail::process_id <= 0);

		printf("pid = %d\n", detail::process_id);

		do
		{
			detail::process_base = get_base_address();
		} while (detail::process_base <= 0);

		printf("base = %p\n", detail::process_base);

		do
		{
			detail::dos_header = read<IMAGE_DOS_HEADER>(detail::process_base);
		} while (detail::dos_header.e_lfanew <= 0);

		detail::nt_headers = read<IMAGE_NT_HEADERS64>(detail::process_base + detail::dos_header.e_lfanew);
		return (detail::process_id > 0 && detail::process_base > 0 && detail::dos_header.e_lfanew > 0 && detail::nt_headers.OptionalHeader.SizeOfImage > 0);
	}
}