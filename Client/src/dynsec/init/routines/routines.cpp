#include "routines.hpp"
#include "global/variables.hpp"
#include "utils/utils.hpp"
#include "utils/scans/signature_scan.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/secure/module.hpp"
#include "dynsec/crypto/crypto.hpp"

namespace Dynsec::Routines {
	void MemoryScanRoutine(LPVOID lpParam) {
		auto MemoryPages = Utils::Secure::GetMemoryPages();
		
		// 5 is a psuedo number for now, basically want to log if the memory page scan was very low (impossible, really)
		if (MemoryPages.size() <= 5) {
			// Report
		}

		auto start = std::chrono::high_resolution_clock::now();
		for (auto& Page : MemoryPages) {
			// Code sections, etc
			bool ExecutableMemory =
				(Page.Protect == PAGE_EXECUTE
					|| Page.Protect == PAGE_EXECUTE_READ
					|| Page.Protect == PAGE_EXECUTE_READWRITE
					|| Page.Protect == PAGE_EXECUTE_WRITECOPY);

			// Data sections, etc
			bool StorageMemory = 
				(Page.Protect == PAGE_READONLY
					|| Page.Protect == PAGE_READWRITE);

			// Skip pages that aren't executable and aren't read/write
			if (!ExecutableMemory && !StorageMemory) continue;

			for (auto& Signature : Global::Vars::g_MemorySignatures) {
				// TODO: Signature encryption (lightweight RC4)
				if ((Signature.m_Executable && ExecutableMemory)
					|| (!Signature.m_Executable && StorageMemory)) {
					// Process
					if (Signature.m_Signature.size()) {
						uint64_t ScanResult = Utils::Scans::PatternScan((uint64_t)Page.BaseAddress, (uint64_t)Page.BaseAddress + Page.RegionSize, Signature.m_Signature.c_str());
						if (ScanResult && ScanResult != (uint64_t)Signature.m_Signature.data()) {
							printf("Scan %x found at %llx\n", Signature.m_Identifier, ScanResult);
						}
					}
				}
			}
		}

		auto elapsed = std::chrono::high_resolution_clock::now() - start;
		long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
		printf("%i microseconds to scan all memory pages for 1 signature\n", microseconds);

		// Once a minute
		Sleep(OneMinute);
	}

	void ExploitableModuleScanRoutine(LPVOID lpParam) {
		auto MappedModules = Utils::Secure::GetMappedModules();

		for (auto& Module : MappedModules) {
			if (Module) {
				HMODULE ModuleHandle = (HMODULE)(Module->DllBase);
				if (ModuleHandle != Utils::Secure::GetModuleHandle(0)) {
					auto ModuleSections = Utils::Secure::GetModuleSections(ModuleHandle);
					for (auto& Section : ModuleSections) {
						if (Section) {
							if (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE
								&& Section->Characteristics & IMAGE_SCN_MEM_WRITE) {
								if (Module->BaseDllName.Buffer) {
									auto SectionAddress = RVA2VA(uint64_t, ModuleHandle, Section->VirtualAddress);
									printf("%ws is executable and writable (%X)\n", Module->BaseDllName.Buffer, Dynsec::Crypto::CRC32((uint8_t*)SectionAddress, Section->Misc.VirtualSize));
								}

								// Report name, timestamp, crc hash of section
							}
						}
					}
				}
			}
		}

		// Once every 5 minutes
		Sleep(OneMinute * 5);
	}

	void NTAPI ThreadLocalStorageCallback(PVOID DllHandle, DWORD dwReason, PVOID) {
		if (dwReason == DLL_THREAD_ATTACH) {
			uint64_t ThreadEntryPoint = Utils::GetThreadEntryPoint(GetCurrentThread());
			if (ThreadEntryPoint) {
				printf("Thread created with DLL_THREAD_ATTACH at %p (%i)\n", ThreadEntryPoint, dwReason);

				uint64_t PageSize = 0x500;
				for (auto& Signature : Global::Vars::g_ThreadEntrySignatures) {
					// TODO: Signature encryption (lightweight RC4)
					if (Signature.m_Signature.size()) {
						// Scan for signatures
						uint64_t ScanResult = Utils::Scans::PatternScan(ThreadEntryPoint, ThreadEntryPoint + PageSize, Signature.m_Signature.c_str());
						if (ScanResult && ScanResult != (uint64_t)Signature.m_Signature.data()) {
							// Report
							printf("Thread scan %x found at %llx, blocking\n", Signature.m_Identifier, ScanResult);
							ExitThread(0);
							return;
						}

						// Resolve LoadLibrary jumps
						uint8_t JumpAsm[] = { 0x48, 0xFF, 0x25 };
						if (!memcmp((void*)ThreadEntryPoint, JumpAsm, 3)) {
							uint64_t JumpAddress = (uint64_t)(*(int*)(ThreadEntryPoint + 3) + ThreadEntryPoint + 7);
							if (JumpAddress) {
								JumpAddress = *(uint64_t*)(JumpAddress);
								if (JumpAddress == (uint64_t)GetProcAddress(GetModuleHandleA("KERNELBASE.dll"), "LoadLibraryW")) {
									// Using LoadLibraryW
									printf("LoadLibraryW being used to inject, blocking for now\n");
									ExitThread(0);
									return;
									// TODO: Find where the string is thats loading the dll
								}

								printf("JumpAddress: %llx\n", JumpAddress);
							}
						}
					}
				}
			}
		}
	}

	void WindowScanRoutine(LPVOID lpParam) {

		Sleep(OneMinute);
	}

	extern "C" void __fastcall hook_routine(uintptr_t rcx /*return addr*/, uintptr_t rdx /*return result*/) {
		// We want to avoid having a recursion issue if we call other system functions in here
		if (Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()]) {
			return;
		}

		Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()] = true;

		// handle syscall here

		Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()] = false;
	}
}