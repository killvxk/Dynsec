#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
	class Syscalls {
	public:
		struct CryptedAllocItem {
			uint8_t m_Size;
			bool m_Encrypted;
			uint8_t m_XorKey;
			uint8_t m_ShellCode[1];
		};

		bool Initialize();
		void Clean();

		NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
		NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
		NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
		NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
		NTSTATUS NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
		NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
		NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
		NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, int ProcessInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
		NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
	private:
		enum eFunctions {
			_NtAllocateVirtualMemory,
			_NtFreeVirtualMemory,
			_NtProtectVirtualMemory,
			_NtQueryVirtualMemory,
			_NtQuerySystemInformation,
			_NtQueryInformationProcess,
			_NtSetInformationProcess,
			_NtCreateThreadEx,
			_NtQueryInformationThread,
			_NtReadVirtualMemory
		};

		LPVOID m_NtdllDisk = nullptr;
		std::unordered_map<eFunctions, std::pair<CryptedAllocItem*, int>> m_Functions;
		std::unordered_map<eFunctions, std::mutex> m_Mutexs;

		int GetSyscallIndex(const char* pFunction, LPVOID pDisk = nullptr);
	};
	
	Syscalls* GetSyscalls();
}