#pragma once

namespace ntBuild {
	inline constexpr auto Win1803 = 17134;
	inline constexpr auto Win1809 = 17763;
	inline constexpr auto Win1903 = 18362;
	inline constexpr auto Win1909 = 18363;
	inline constexpr auto Win2004 = 19041;
	inline constexpr auto Win20H2 = 19569;
	inline constexpr auto Win21H1 = 20180;
	inline constexpr auto Win11_21H2 = 22000;
	inline constexpr auto Win11_22H2 = 22621;
}

namespace kernel_KPROCESS {

	// !_KPROCESS.UserDirectoryTableBase
	inline unsigned long long UserDirectoryTableBase = 0;
}

namespace kernel_EPROCESS {

	// !_EPROCESS.SectionBaseAddress
	inline unsigned long long SectionBaseAddress = 0;
}

inline bool initalizeOffsets() {

	RTL_OSVERSIONINFOW os_version_info;
	RtlGetVersion(&os_version_info);
	NtBuildNumber = os_version_info.dwBuildNumber;

	if (NtBuildNumber == ntBuild::Win1803) 
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x278;
		kernel_EPROCESS::SectionBaseAddress = 0x3c0;
	}
	else if (NtBuildNumber == ntBuild::Win1809)
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x278;
		kernel_EPROCESS::SectionBaseAddress = 0x3c0;
	}
	else if (NtBuildNumber == ntBuild::Win1903) 
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x280;
		kernel_EPROCESS::SectionBaseAddress = 0x3c8;
	}
	else if (NtBuildNumber == ntBuild::Win1909)
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x280;
		kernel_EPROCESS::SectionBaseAddress = 0x3c8;
	}
	else if (NtBuildNumber == ntBuild::Win2004) 
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x388;
		kernel_EPROCESS::SectionBaseAddress = 0x520;
	}
	else if (NtBuildNumber == ntBuild::Win21H1)
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x388;
		kernel_EPROCESS::SectionBaseAddress = 0x520;
	}
	else if (NtBuildNumber == ntBuild::Win11_21H2) 
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x388;
		kernel_EPROCESS::SectionBaseAddress = 0x520;
	}
	else if (NtBuildNumber == ntBuild::Win11_22H2) 
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x388;
		kernel_EPROCESS::SectionBaseAddress = 0x520;
	}
	else
	{
		kernel_KPROCESS::UserDirectoryTableBase = 0x388;
		kernel_EPROCESS::SectionBaseAddress = 0x520;
	}

	return (kernel_KPROCESS::UserDirectoryTableBase != 0 && kernel_EPROCESS::SectionBaseAddress != 0);
}