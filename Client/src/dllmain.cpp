#include "stdafx.hpp"
#include "dynsec/init/init.hpp"
#include "utils/secure/module.hpp"
extern "C" {
	__declspec(dllexport) void InitializeClient(void* pDynsecData) {
		// caller checks here
		return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::Callbacks*>(pDynsecData));
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        auto start = std::chrono::high_resolution_clock::now();

        char name[MAX_PATH];
        if (GetModuleFileNameA(GetModuleHandleA("ntdll.dll"), name, MAX_PATH)) {
            FILE* fp;
            fopen_s(&fp, name, "rb");
            if (fp) {
                fseek(fp, 0, SEEK_END);
                int size = ftell(fp);
                fseek(fp, 0, SEEK_SET);

				printf("Allocating %x bytes...\n", size);
                auto memory = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (memory) {
                    fread(memory, 1, size, fp);
                    fclose(fp);

                    auto elapsed = std::chrono::high_resolution_clock::now() - start;
                    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

                    printf("base: %llx\n", memory);
                    printf("%i microseconds\n", microseconds);
					printf("\nExpected value: %p\n", *(uintptr_t*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory"));
                    printf("Value: %p\n\n", *(uintptr_t*)Utils::Secure::GetProcAddressDisk((HMODULE)memory, "NtQueryVirtualMemory"));

                    VirtualFree(memory, 0, MEM_RELEASE);
                }
            }
        }
    }

    return TRUE;
}