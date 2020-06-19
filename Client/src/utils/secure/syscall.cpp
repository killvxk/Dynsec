#include "syscall.hpp"
#include "utils/caller.hpp"
#include "module.hpp"
#include "dynsec/crypto/crypto.hpp"
#include "utils/secure/pointers.hpp"

namespace Utils::Secure {
	void EncryptAllocation(Syscalls::CryptedAllocItem* Address) {
		if (!Address->m_Encrypted) {
			// on the stack for extra poggers - "supa secret key"
			uint8_t key[] = { 0x73, 0x75, 0x70, 0x61, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x6B, 0x65, 0x79 };
			Dynsec::Crypto::RC4(key, sizeof(key), Address->m_ShellCode, Address->m_Size);

			// random key each time
			Address->m_XorKey = (uint8_t)(rand() % 255);

			for (uint8_t i = 0; i < Address->m_Size; i++) {
				Address->m_ShellCode[i] ^= Address->m_XorKey;
			}

			Address->m_Encrypted = true;
		}
	}

	void DecryptAllocation(Syscalls::CryptedAllocItem* Address) {
		if (Address->m_Encrypted) {
			// random key each time
			for (uint8_t i = 0; i < Address->m_Size; i++) {
				Address->m_ShellCode[i] ^= Address->m_XorKey;
			}

			// on the stack for extra poggers - "supa secret key"
			uint8_t key[] = { 0x73, 0x75, 0x70, 0x61, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x6B, 0x65, 0x79 };
			Dynsec::Crypto::RC4(key, sizeof(key), Address->m_ShellCode, Address->m_Size);

			Address->m_Encrypted = false;
		}
	}

	void SetupAllocation(std::pair<LPVOID, int> lpAddress, const char* SyscallShellcode, uint8_t ShellcodeSize, uint8_t ShellcodeIndexOffset, bool Encoded = true) {
		Syscalls::CryptedAllocItem* Address = nullptr;

		if (Encoded) {
			Address = (Syscalls::CryptedAllocItem*)DecodePtr(lpAddress.first);
		} else Address = (Syscalls::CryptedAllocItem*)lpAddress.first;

		memcpy(&Address->m_ShellCode, SyscallShellcode, ShellcodeSize);
		*(int*)(&Address->m_ShellCode[ShellcodeIndexOffset]) = lpAddress.second;

		Address->m_Size = ShellcodeSize;
		EncryptAllocation(Address);
	}

	bool Syscalls::Initialize() {
		auto start = std::chrono::high_resolution_clock::now();

		// TODO: Syscall shellcode for each windows versions

#ifdef _WIN64
		// 4C 8B D1 B8 99 00 00 00 0F 05 C3
		const char* SyscallShellcode = "\x49\x89\xCA\xB8\x99\x00\x00\x00\x0F\x05\xC3";
		uint8_t ShellcodeIndexOffset = 4;
		uint8_t ShellcodeSize = 11;
#else
		const char* SyscallShellcode = "\xB8\x99\x00\x00\x00\xCD\x2E\xC3";
		uint8_t ShellcodeIndexOffset = 1;
		uint8_t ShellcodeSize = 8;
#endif

		auto CheckAllocation = [this](LPVOID lpAddress) {
			if (!lpAddress) {
				Clean();
				return false;
			}

			return true;
		};

		auto SecureVirtualAlloc = [&](LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID {
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

				m_NtdllDisk = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
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
		m_Functions[_NtQueryInformationProcess].second = GetSyscallIndex("NtQueryInformationProcess", m_NtdllDisk);
		m_Functions[_NtSetInformationProcess].second = GetSyscallIndex("NtSetInformationProcess", m_NtdllDisk);
		m_Functions[_NtCreateThreadEx].second = GetSyscallIndex("NtCreateThreadEx", m_NtdllDisk);
		m_Functions[_NtQueryInformationThread].second = GetSyscallIndex("NtQueryInformationThread", m_NtdllDisk);
		m_Functions[_NtReadVirtualMemory].second = GetSyscallIndex("NtReadVirtualMemory", m_NtdllDisk);
		m_Functions[_NtSetInformationThread].second = GetSyscallIndex("NtSetInformationThread", m_NtdllDisk);

		if (m_NtdllDisk) VirtualFree(m_NtdllDisk, 0, MEM_RELEASE);

		m_Functions[_NtAllocateVirtualMemory].first = (CryptedAllocItem*)VirtualAlloc(0, ShellcodeSize + sizeof(CryptedAllocItem) - 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtAllocateVirtualMemory].first)) return false;
		SetupAllocation(m_Functions[_NtAllocateVirtualMemory], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset, false);

		m_Functions[_NtQueryInformationProcess].first = (CryptedAllocItem*)VirtualAlloc(0, ShellcodeSize + sizeof(CryptedAllocItem) - 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!CheckAllocation(m_Functions[_NtQueryInformationProcess].first)) return false;
		SetupAllocation(m_Functions[_NtQueryInformationProcess], SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset, false);

		// encrypt the two ptrs not encrypted
		m_Functions[_NtQueryInformationProcess].first = (CryptedAllocItem*)EncodePtr(m_Functions[_NtQueryInformationProcess].first);
		m_Functions[_NtAllocateVirtualMemory].first = (CryptedAllocItem*)EncodePtr(m_Functions[_NtAllocateVirtualMemory].first);

		// now that the above syscall is resolved, we can use the secure ptrs
		for (auto& Element : m_Functions) {
			Element.second.first = (CryptedAllocItem*)EncodePtr(SecureVirtualAlloc(0, ShellcodeSize + sizeof(CryptedAllocItem) - 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
			if (!CheckAllocation(Element.second.first)) return false;
			SetupAllocation(Element.second, SyscallShellcode, ShellcodeSize, ShellcodeIndexOffset);
		}

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

	std::vector<uint64_t> Syscalls::GetAllocatedAddresses() {
		std::vector<uint64_t> Addresses;

		for (auto Element : m_Functions) {
			Addresses.push_back((uint64_t)Element.second.first);
		}

		return Addresses;
	}

	NTSTATUS Syscalls::NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtAllocateVirtualMemory]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtAllocateVirtualMemory].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtFreeVirtualMemory]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtFreeVirtualMemory].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, BaseAddress, RegionSize, FreeType);
		EncryptAllocation(Address);

		m_Mutexs[_NtFreeVirtualMemory].unlock();
		return Return;
	}

	NTSTATUS Syscalls::NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtProtectVirtualMemory]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtProtectVirtualMemory].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtQueryVirtualMemory]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtQueryVirtualMemory].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtQuerySystemInformation]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtQuerySystemInformation].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtQueryInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
		static bool FirstCall = true;

		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtQueryInformationProcess]);
		CryptedAllocItem* Address = nullptr;

		if (FirstCall) {
			FirstCall = false;
			Address = (CryptedAllocItem*)m_Functions[_NtQueryInformationProcess].first;
		} else {
			Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtQueryInformationProcess].first);
		}

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtSetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtSetInformationProcess]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtSetInformationProcess].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtCreateThreadEx]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtCreateThreadEx].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
		EncryptAllocation(Address);

		return Return;
	}


	NTSTATUS Syscalls::NtQueryInformationThread(HANDLE ThreadHandle, int ProcessInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtQueryInformationThread]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtQueryInformationThread].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ThreadHandle, ProcessInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtReadVirtualMemory]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtReadVirtualMemory].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
		EncryptAllocation(Address);

		return Return;
	}

	NTSTATUS Syscalls::NtSetInformationThread(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
		NTSTATUS Return = 0;

		std::unique_lock<std::mutex> l(m_Mutexs[_NtSetInformationThread]);
		CryptedAllocItem* Address = (CryptedAllocItem*)DecodePtr(m_Functions[_NtSetInformationThread].first);

		DecryptAllocation(Address);
		Return = Utils::Caller::Call<NTSTATUS>((uint64_t)&Address->m_ShellCode, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		EncryptAllocation(Address);

		return Return;
	}

	Syscalls* GetSyscalls() {
		static Syscalls Instance;
		return &Instance;
	}
}