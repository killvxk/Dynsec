#include "syscall.hpp"
#include "utils/caller.hpp"
#include "module.hpp"

namespace Utils::Secure {
	void EncryptAllocation(uint64_t Address) {
		if (*(uint8_t*)(Address + 1) != 1) {
			for (uint8_t i = 0; i < *(uint8_t*)(Address); i++) {
				*(uint8_t*)(Address + i + 2) ^= 0x69;
			}

			*(uint8_t*)(Address + 1) = 1;
		}
	}

	void DecryptAllocation(uint64_t Address) {
		if (*(uint8_t*)(Address + 1) == 1) {
			for (uint8_t i = 0; i < *(uint8_t*)(Address); i++) {
				*(uint8_t*)(Address + i + 2) ^= 0x69;
			}

			*(uint8_t*)(Address + 1) = 0;
		}
	}

	void SetupAllocation(std::pair<LPVOID, int> lpAddress, const char* SyscallShellcode, uint8_t ShellcodeSize, uint8_t ShellcodeIndexOffset) {
		uint64_t Address = (uint64_t)lpAddress.first;

		memcpy((void*)(Address + 2), SyscallShellcode, ShellcodeSize);
		*(int*)(Address + ShellcodeIndexOffset + 2) = lpAddress.second;

		*(uint8_t*)(Address) = ShellcodeSize;
		EncryptAllocation(Address);
	}

	bool Syscalls::Initialize() {
		auto start = std::chrono::high_resolution_clock::now();

#ifdef _WIN64
		static const char* SyscallShellcode = "\x49\x89\xCA\xB8\x99\x00\x00\x00\x0F\x05\xC3";
		uint8_t ShellcodeIndexOffset = 4;
		uint8_t ShellcodeSize = 11;
#else
		static const char* SyscallShellcode = "\xB8\x99\x00\x00\x00\xCD\x2E\xC3";
		uint8_t ShellcodeIndexOffset = 1;
		uint8_t ShellcodeSize = 8;
#endif

		auto CheckAllocation = [this] (LPVOID lpAddress) {
			if (!lpAddress) {
				Clean();
				return false;
			}

			return true;
		};

		auto SecureVirtualAlloc = [&] (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID {
			if (NtAllocateVirtualMemory(GetCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect) >= 0) {
				return lpAddress;
			}

			return nullptr;
		};

		char name[MAX_PATH];
		if (GetModuleFileNameA(Utils::Secure::GetModuleHandle(L"ntdll.dll"), name, MAX_PATH)) {
			FILE* fp;
			fopen_s(&fp, name, "rb");
			if (fp) {
				fseek(fp, 0, SEEK_END);
				int size = ftell(fp);
				fseek(fp, 0, SEEK_SET);

				m_NtdllDisk = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (m_NtdllDisk) {
					fread(m_NtdllDisk, 1, size, fp);
					fclose(fp);
				}
			}
		}

		m_Functions[_NtAllocateVirtualMemory].second = GetSyscallIndex("NtAllocateVirtualMemory", m_NtdllDisk);
		m_Functions[_NtFreeVirtualMemory].second = GetSyscallIndex("NtFreeVirtualMemory", m_NtdllDisk);
		m_Functions[_NtProtectVirtualMemory].second = GetSyscallIndex("NtProtectVirtualMemory", m_NtdllDisk);
		m_Functions[_NtQueryVirtualMemory].second = GetSyscallIndex("NtQueryVirtualMemory", m_NtdllDisk);
		m_Functions[_NtQuerySystemInformation].second = GetSyscallIndex("NtQuerySystemInformation", m_NtdllDisk);
		m_Functions[_NtQueryProcessInformation].second = GetSyscallIndex("NtQueryProcessInformation", m_NtdllDisk);

		if (m_NtdllDisk) VirtualFree(m_NtdllDisk, 0, MEM_RELEASE);

		m_Functions[_NtAllocateVirtualMemory].first = VirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtAllocateVirtualMemory].first)) return false;
		SetupAllocation(m_Functions[_NtAllocateVirtualMemory], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);

		m_Functions[_NtFreeVirtualMemory].first = SecureVirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtFreeVirtualMemory].first)) return false;
		SetupAllocation(m_Functions[_NtFreeVirtualMemory], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);

		m_Functions[_NtProtectVirtualMemory].first = SecureVirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtProtectVirtualMemory].first)) return false;
		SetupAllocation(m_Functions[_NtProtectVirtualMemory], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);

		m_Functions[_NtQueryVirtualMemory].first = SecureVirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtQueryVirtualMemory].first)) return false;
		SetupAllocation(m_Functions[_NtQueryVirtualMemory], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);

		m_Functions[_NtQuerySystemInformation].first = SecureVirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtQuerySystemInformation].first)) return false;
		SetupAllocation(m_Functions[_NtQuerySystemInformation], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);

		m_Functions[_NtQueryProcessInformation].first = SecureVirtualAlloc(0, ShellcodeSize + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtQueryProcessInformation].first)) return false;
		SetupAllocation(m_Functions[_NtQueryProcessInformation], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);
		
		auto elapsed = std::chrono::high_resolution_clock::now() - start;
		long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
		printf("%i microseconds to initialize syscalls\n", microseconds);

		return true;
	}

	int Syscalls::GetSyscallIndex(const char* pFunction, LPVOID pDisk) {
		FARPROC FunctionAddress = 0;

		if (pDisk) {
			FunctionAddress = Utils::Secure::GetProcAddressDisk((HMODULE)pDisk, pFunction);
		} else FunctionAddress = Utils::Secure::GetProcAddress(Utils::Secure::GetModuleHandle(L"ntdll.dll"), pFunction);

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
		for (auto& it : m_Functions) {
			VirtualFree(it.second.first, 0, MEM_RELEASE);
		}
	}

	NTSTATUS Syscalls::NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtAllocateVirtualMemory].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtAllocateVirtualMemory].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		EncryptAllocation(Address);

		m_Mutexs[_NtAllocateVirtualMemory].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtFreeVirtualMemory].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtFreeVirtualMemory].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, ProcessHandle, BaseAddress, RegionSize, FreeType);
		EncryptAllocation(Address);

		m_Mutexs[_NtFreeVirtualMemory].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtProtectVirtualMemory].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtProtectVirtualMemory].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
		EncryptAllocation(Address);

		m_Mutexs[_NtProtectVirtualMemory].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtQueryVirtualMemory].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtQueryVirtualMemory].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
		EncryptAllocation(Address);

		m_Mutexs[_NtQueryVirtualMemory].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtQuerySystemInformation].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtQuerySystemInformation].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		EncryptAllocation(Address);

		m_Mutexs[_NtQuerySystemInformation].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtQueryProcessInformation(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
		NTSTATUS Return = 0;

		m_Mutexs[_NtQueryProcessInformation].lock();
		uint64_t Address = (uint64_t)m_Functions[_NtQueryProcessInformation].first;

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>(Address + 2, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		EncryptAllocation(Address);

		m_Mutexs[_NtQueryProcessInformation].unlock();
		return Return;
	}

	Syscalls* GetSyscalls() {
		static Syscalls instance;
		return &instance;
	}
}