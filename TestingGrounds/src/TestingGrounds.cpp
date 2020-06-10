#include <Windows.h>
#include <iostream>
#include <chrono>

DWORD WINAPI Thread(LPVOID) {
    printf("thread called\n");
    return 0;
}

int main() {
    struct Callbacks {

    };

    printf("loading...\n");
	HMODULE Dynsec = LoadLibraryA("Client.dll");
	printf("loaded\n");
    if (Dynsec) {
        printf("Dynsec client: %llx\n", Dynsec);
        FARPROC Initialize = GetProcAddress(Dynsec, "InitializeClient");
        if (Initialize) {
            printf("InitializeClient: %llx\n", Initialize);
            Callbacks* Data = new Callbacks();
            ((void(*)(Callbacks*))Initialize)(Data);

            // temp
            delete Data;
        }
    }

    system("pause");
}