#include "module.hpp"

namespace Utils::Secure {
	HMODULE GetModuleHandle(const wchar_t* moduleName) {
		LoadLibraryW(moduleName);

		auto MappedModules = GetMappedModules();
		for (auto Module : MappedModules) {
			if (moduleName == nullptr) {
				return (HMODULE)Module->DllBase;
			}

			if (Module->BaseDllName.Buffer && Module->BaseDllName.Length) {
				if (!wcscmp(Module->BaseDllName.Buffer, moduleName)) {
					return (HMODULE)Module->DllBase;
				}
			}
		}

		return 0;
	}

	uintptr_t FindRawAddress(PIMAGE_NT_HEADERS ntHeader, uintptr_t va) {
		// Since sections contains both a raw address and virtual address field,
		// we can use it to get the raw address from a virtual address.
		auto section = IMAGE_FIRST_SECTION(ntHeader);
		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			if (va >= section->VirtualAddress &&
				va <= (section->VirtualAddress + section->Misc.VirtualSize)) {

				uintptr_t offset = va - section->VirtualAddress;
				uintptr_t rawAddress = section->PointerToRawData + offset;

				return rawAddress;
			}
			section++;
		}

		return 0;
	}

	template<class T>
	T FindRawPointer(PIMAGE_NT_HEADERS headers, HMODULE hMod, uintptr_t va) {
		return (T)((uintptr_t)hMod + FindRawAddress(headers, va));
	}

	FARPROC GetProcAddressDisk(HMODULE hMod, const char* procName) {
		PIMAGE_NT_HEADERS ntHeader = RVA2VA(PIMAGE_NT_HEADERS, hMod, ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (!ntHeader)
			return nullptr;

		PIMAGE_DATA_DIRECTORY dataDirectory = ntHeader->OptionalHeader.DataDirectory;

		DWORD exportsVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		PIMAGE_EXPORT_DIRECTORY pExports = FindRawPointer<PIMAGE_EXPORT_DIRECTORY>(ntHeader, hMod, exportsVA);

		if (pExports) {
			uint16_t* nameOrdinals = FindRawPointer<uint16_t*>(ntHeader, hMod, pExports->AddressOfNameOrdinals);
			uint32_t* functions = FindRawPointer<uint32_t*>(ntHeader, hMod, pExports->AddressOfFunctions);
			uint32_t* names = FindRawPointer<uint32_t*>(ntHeader, hMod, pExports->AddressOfNames);


			if (nameOrdinals && functions && names) {
				for (uint32_t i = 0; i < pExports->NumberOfFunctions; i++) {
					const char* exportName = FindRawPointer<const char*>(ntHeader, hMod, names[i]);
					if (exportName && !strcmp(exportName, procName)) {
						uint32_t offset = functions[nameOrdinals[i]];
						if (offset)
							return FindRawPointer<FARPROC>(ntHeader, hMod, offset);

					}
				}
			}
		}
		return nullptr;
	}

	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName) {
		if (moduleHandle) {
			PIMAGE_NT_HEADERS NtHeader = RVA2VA(PIMAGE_NT_HEADERS, moduleHandle, ((PIMAGE_DOS_HEADER)moduleHandle)->e_lfanew);
			if (NtHeader) {
				PIMAGE_DATA_DIRECTORY DataDirectory = NtHeader->OptionalHeader.DataDirectory;
				if (DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
					PIMAGE_EXPORT_DIRECTORY Exports = nullptr;

					Exports = RVA2VA(PIMAGE_EXPORT_DIRECTORY, moduleHandle, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

					if (Exports) {
						uint16_t* NameOridinals = RVA2VA(uint16_t*, moduleHandle, Exports->AddressOfNameOrdinals);
						uint32_t* Functions = RVA2VA(uint32_t*, moduleHandle, Exports->AddressOfFunctions);
						uint32_t* Names = RVA2VA(uint32_t*, moduleHandle, Exports->AddressOfNames);

						if (NameOridinals && Functions && Names) {
							for (uint32_t i = 0; i < Exports->NumberOfFunctions; i++) {
								const char* ExportName = RVA2VA(const char*, moduleHandle, Names[i]);
								if (ExportName && !strcmp(ExportName, procName)) {
									uint32_t Offset = Functions[RVA2VA(uint16_t, moduleHandle, NameOridinals[i])];
									if (Offset) {
										return (FARPROC)((uint64_t)moduleHandle + Offset);
									}
								}
							}
						}
					}
				}
			}
		}

		return nullptr;
	}

	std::vector<PIMAGE_SECTION_HEADER> GetModuleSections(HMODULE hModule) {
		std::vector<PIMAGE_SECTION_HEADER> Headers;

		PIMAGE_NT_HEADERS NtHeader = RVA2VA(PIMAGE_NT_HEADERS, hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
		if (!NtHeader) {
			return Headers;
		}

		PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
			Headers.push_back(SectionHeader);
			SectionHeader++;
		}

		return Headers;
	}

	std::vector<PLDR_DATA_TABLE_ENTRY> GetMappedModules() {
		std::vector<PLDR_DATA_TABLE_ENTRY> Modules;

		if (ProcessEnvironmentBlock) {
			PPEB_LDR_DATA Ldr = ProcessEnvironmentBlock->Ldr;
			if (Ldr) {
				PLIST_ENTRY CurrentEntry = Ldr->InLoadOrderModuleList.Flink;
				if (CurrentEntry) {
					while (CurrentEntry != &Ldr->InLoadOrderModuleList && CurrentEntry != nullptr) {
						PLDR_DATA_TABLE_ENTRY Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (Current) {
							Modules.push_back(Current);
						}

						CurrentEntry = CurrentEntry->Flink;
					}
				}
			}
		}

		return Modules;
	}
}