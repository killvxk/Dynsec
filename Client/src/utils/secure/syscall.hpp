#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
	class Syscalls {
	public:
		bool Initialize();
		void Clean();

		NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
		NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
		NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
		NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
		NTSTATUS NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		NTSTATUS NtQueryProcessInformation(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	private:
		LPVOID m_NtAllocateVirtualMemoryAddress;
		LPVOID m_NtFreeVirtualMemoryAddress;
		LPVOID m_NtProtectVirtualMemoryAddress;
		LPVOID m_NtQueryVirtualMemoryAddress;
		LPVOID m_NtQuerySystemInformationAddress;
		LPVOID m_NtQueryProcessInformationAddress;

		int GetSyscallIndex(const char* pFunction);
	};
	
	Syscalls* GetSyscalls();
}