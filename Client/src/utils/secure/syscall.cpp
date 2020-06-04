#include "syscall.hpp"
#include "utils/caller.hpp"
#include "module.hpp"

namespace Utils::Secure {
	bool Syscalls::Initialize() {
#ifdef _WIN64
		const char* SyscallShellcode = "\x49\x89\xCA\xB8\x99\x00\x00\x00\x0F\x05\xC3";
		uint8_t ShellcodeIndexOffset = 4;
		SIZE_T ShellcodeSize = 11;
#else
		const char* SyscallShellcode = "\xB8\x99\x00\x00\x00\xCD\x2E\xC3";
		uint8_t ShellcodeIndexOffset = 1;
		SIZE_T ShellcodeSize = 8;
#endif

		auto CheckAllocation = [this] (LPVOID lpAddress) {
			if (!lpAddress) {
				Clean();
				return false;
			}

			return true;
		};

		auto SecureVirtualAlloc = [&] (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID {
			NTSTATUS ret = NtAllocateVirtualMemory(GetCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect);
			if (ret >= 0) {
				return lpAddress;
			}

			return nullptr;
		};

		m_NtAllocateVirtualMemoryAddress = VirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtAllocateVirtualMemoryAddress)) return false;
		memcpy(m_NtAllocateVirtualMemoryAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtAllocateVirtualMemoryAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtAllocateVirtualMemory");

		m_NtFreeVirtualMemoryAddress = SecureVirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtFreeVirtualMemoryAddress)) return false;
		memcpy(m_NtFreeVirtualMemoryAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtFreeVirtualMemoryAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtFreeVirtualMemory");

		m_NtProtectVirtualMemoryAddress = SecureVirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtProtectVirtualMemoryAddress)) return false;
		memcpy(m_NtProtectVirtualMemoryAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtProtectVirtualMemoryAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtProtectVirtualMemory");

		m_NtQueryVirtualMemoryAddress = SecureVirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtQueryVirtualMemoryAddress)) return false;
		memcpy(m_NtQueryVirtualMemoryAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtQueryVirtualMemoryAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtQueryVirtualMemory");

		m_NtQuerySystemInformationAddress = SecureVirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtQuerySystemInformationAddress)) return false;
		memcpy(m_NtQuerySystemInformationAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtQuerySystemInformationAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtQuerySystemInformation");

		m_NtQueryProcessInformationAddress = SecureVirtualAlloc(0, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_NtQueryProcessInformationAddress)) return false;
		memcpy(m_NtQueryProcessInformationAddress, SyscallShellcode, ShellcodeSize);
		*(int*)((uint64_t)m_NtQueryProcessInformationAddress + ShellcodeIndexOffset) = GetSyscallIndex("NtQueryProcessInformation");
		
		return true;
	}

	int Syscalls::GetSyscallIndex(const char* pFunction) {
		// TODO: get from disk instead
		FARPROC FunctionAddress = Utils::Secure::GetProcAddress(Utils::Secure::GetModuleHandle(L"ntdll.dll"), pFunction);
		if (FunctionAddress) {
			uint64_t Address = (uint64_t)FunctionAddress;
#ifdef _WIN64
			if (*(uint8_t*)Address == 0x49 || *(uint8_t*)Address == 0x4C) {
				return *(int*)(Address + 4);
			}
#else
			if (*(uint8_t*)Address == 0xB8) {
				return *(int*)(Address + 1);
			}
#endif
		}

		return 0;
	}

	void Syscalls::Clean() {
		VirtualFree(m_NtAllocateVirtualMemoryAddress, 0, MEM_RELEASE);
		VirtualFree(m_NtFreeVirtualMemoryAddress, 0, MEM_RELEASE);
		VirtualFree(m_NtProtectVirtualMemoryAddress, 0, MEM_RELEASE);
		VirtualFree(m_NtQueryVirtualMemoryAddress, 0, MEM_RELEASE);
		VirtualFree(m_NtQuerySystemInformationAddress, 0, MEM_RELEASE);
		VirtualFree(m_NtQueryProcessInformationAddress, 0, MEM_RELEASE);
	}

	NTSTATUS Syscalls::NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtAllocateVirtualMemoryAddress, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	NTSTATUS Syscalls::NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtFreeVirtualMemoryAddress, ProcessHandle, BaseAddress, RegionSize, FreeType);
	}

	NTSTATUS Syscalls::NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtProtectVirtualMemoryAddress, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

	NTSTATUS Syscalls::NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtQueryVirtualMemoryAddress, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}

	NTSTATUS Syscalls::NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtQuerySystemInformationAddress, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	NTSTATUS Syscalls::NtQueryProcessInformation(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
		return Utils::Caller::Call<NTSTATUS>((uint64_t)m_NtQueryProcessInformationAddress, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}

	Syscalls* GetSyscalls() {
		static Syscalls instance;
		return &instance;
	}
}