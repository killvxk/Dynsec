#include "module.hpp"
#include "structs.hpp"

namespace Utils::Module {
#define RVA2VA(type, base, rva) (type)((uint64_t)base + rva)
#define VA2RVA(type, base, va) (type)((uint64_t)va - (uint64_t)base)

	HMODULE GetModuleHandle(const wchar_t* moduleName) {
		if (ProcessEnvironmentBlock) {
			PPEB_LDR_DATA Ldr = ProcessEnvironmentBlock->Ldr;
			if (Ldr) {
				PLIST_ENTRY CurrentEntry = Ldr->InLoadOrderModuleList.Flink;
				if (CurrentEntry) {
					while (CurrentEntry != &Ldr->InLoadOrderModuleList && CurrentEntry != nullptr) {
						PLDR_DATA_TABLE_ENTRY Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (Current) {
							if (moduleName == nullptr) {
								return (HMODULE)Current->DllBase;
							}

							if (Current->BaseDllName.Buffer && Current->BaseDllName.Length) {
								if (!wcscmp(Current->BaseDllName.Buffer, moduleName)) {
									return (HMODULE)Current->DllBase;
								}
							}
						}

						CurrentEntry = CurrentEntry->Flink;
					}
				}
			}
		}

		return 0;
	}

	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName) {
		if (moduleHandle) {
			PIMAGE_NT_HEADERS NtHeader = RVA2VA(PIMAGE_NT_HEADERS, moduleHandle, ((PIMAGE_DOS_HEADER)moduleHandle)->e_lfanew);
			PIMAGE_DATA_DIRECTORY DataDirectory = NtHeader->OptionalHeader.DataDirectory;

			if (DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
				PIMAGE_EXPORT_DIRECTORY Exports = RVA2VA(PIMAGE_EXPORT_DIRECTORY, moduleHandle, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				if (Exports) {
					uint16_t* NameOridinals = RVA2VA(uint16_t*, moduleHandle, Exports->AddressOfNameOrdinals);
					uint32_t* Functions = RVA2VA(uint32_t*, moduleHandle, Exports->AddressOfFunctions);
					uint32_t* Names = RVA2VA(uint32_t*, moduleHandle, Exports->AddressOfNames);

					if (NameOridinals && Functions && Names) {
						for (uint32_t i = 0; i < Exports->NumberOfFunctions; i++) {
							const char* ExportName = RVA2VA(const char*, moduleHandle, Names[i]);
							if (ExportName && !strcmp(ExportName, procName)) {
								uint32_t* Offset = &Functions[RVA2VA(uint16_t, moduleHandle, NameOridinals[i])];
								if (Offset) {
									return (FARPROC)((uint64_t)moduleHandle + *Offset);
								}
							}
						}
					}
				}
			}
		}

		return nullptr;
	}
}