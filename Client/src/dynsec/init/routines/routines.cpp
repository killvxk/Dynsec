#include "routines.hpp"
#include "global/variables.hpp"
#include "utils/utils.hpp"
#include "utils/scans/signature_scan.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/secure/module.hpp"
#include "utils/secure/syscall.hpp"
#include "dynsec/crypto/crypto.hpp"
#include "utils/secure/pointers.hpp"

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

			// Check for allocated executable pages outside of mapped modules
			if ((Page.Type == MEM_PRIVATE || Page.Type == MEM_MAPPED) && ExecutableMemory) {
				uint64_t PageAddress = (uint64_t)Page.BaseAddress;

				// Check if the address is in any modules (thanks BE)
				if ((PageAddress & 0xFF0000000000) != 0x7F0000000000
					&& (PageAddress & 0xFFF000000000) != 0x7F000000000
					&& (PageAddress & 0xFFFFF0000000) != 0x70000000
					&& PageAddress != 0x3E0000) {
					bool IsSyscallAllocation = false;
					for (uint64_t SyscallAddress : Utils::Secure::GetSyscalls()->GetAllocatedAddresses()) {
						uint64_t DecodedSyscallAddress = (uint64_t)DecodePtr((void*)SyscallAddress);
						if (DecodedSyscallAddress == PageAddress) {
							IsSyscallAllocation = true;
							break;
						}
					}

					if (!IsSyscallAllocation) {
						// Report
						printf("Executable memory outside of a mapped module at %llx\n", PageAddress);
					}
				}
			}
		}

		auto elapsed = std::chrono::high_resolution_clock::now() - start;
		long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
		printf("%i microseconds to scan all memory pages for 1 signature\n", microseconds);

		// Once a minute
		Sleep(1min);
	}

	void ExploitableModuleScanRoutine(LPVOID lpParam) {
		auto MappedModules = Utils::Secure::GetMappedModules();

		for (auto& Module : MappedModules) {
			if (Module) {
				HMODULE ModuleHandle = (HMODULE)(Module->DllBase);
				if (ModuleHandle != Utils::Secure::GetModuleHandle(0)) {
					// Check for executable+writable sections
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
		Sleep(5min);
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

						// TEMP: Resolve jumps
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
		// TODO: Reverse EnumWindows

		std::vector<Dynsec::RoutineTypes::WindowInfo> Windows;
		BOOL SuccessfullyEnumerated = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
			// Get window name
			char WindowName[100];
			int WindowNameLength = GetWindowTextA(hwnd, WindowName, 100);

			LONG WindowStyle = GetWindowLong(hwnd, GWL_STYLE);
			LONG WindowExtendedStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

			DWORD OwningProcessID = 0;
			GetWindowThreadProcessId(hwnd, &OwningProcessID);

			std::vector<Dynsec::RoutineTypes::WindowInfo>& pWindows = *reinterpret_cast<std::vector<Dynsec::RoutineTypes::WindowInfo>*>(lParam);
			pWindows.push_back({ WindowName, WindowStyle, WindowExtendedStyle, GetCurrentProcessId() == OwningProcessID });
			return TRUE;
		}, (LPARAM)&Windows);

		std::vector<Dynsec::RoutineTypes::WindowInfo> ReportWindows;

		// Iterate without checking if it was successful, just in case
		for (auto& Window : Windows) {
			// Check for matching names

			bool MatchingName = false;
			if (!Window.m_Name.empty()) {
				for (auto& Name : Global::Vars::g_WindowTitleSignatures) {
					if (strstr(Name.c_str(), Window.m_Name.c_str())) {
						MatchingName = true;
						break;
					}
				}
			}

			// If it matches any conds for styles, report here
			if (MatchingName) {
				auto Exists = std::find_if(ReportWindows.begin(), ReportWindows.end(), [&](Dynsec::RoutineTypes::WindowInfo& Info) {
					return !Info.m_Name.compare(Window.m_Name);
				});

				if (Exists == ReportWindows.end()) {
					ReportWindows.push_back(Window);
				}
			}
		}

		printf("[REPORT] Reporting %i windows\n", ReportWindows.size());
		for (auto& Window : ReportWindows) {
			// Report
			printf("[REPORT] Reporting window -> %s\n", Window.m_Name.c_str());
		}

		if (!SuccessfullyEnumerated || Windows.size() < 1) {
			// Report GetLastError
			printf("[REPORT] Window iteration failed (lasterr: %i)\n", GetLastError());
		}

		Sleep(1min);
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