#include <Windows.h>
#include <iostream>
#include <chrono>
#include <iostream>

DWORD WINAPI Thread(LPVOID) {
    printf("thread called\n");
    return 0;
}

int main() {
	// We want it packed this way to match C#
#pragma pack(push, 1)
    struct Callbacks {

    };
#pragma pack(pop)

    printf("loading...\n");
	HMODULE Dynsec = LoadLibraryA("Client.dll");
	printf("loaded\n");
    if (Dynsec) {
        printf("Dynsec client: %llx\n", Dynsec);
        FARPROC Initialize = GetProcAddress(Dynsec, "InitializeClient");
        if (Initialize) {
            printf("InitializeClient: %llx\n", Initialize);
            Callbacks* Data = new Callbacks();
            ((void(__stdcall*)(Callbacks*))Initialize)(Data);

            // temp
            delete Data;
        }
    }

    std::cin.get();
}