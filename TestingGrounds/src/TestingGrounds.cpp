#include <Windows.h>
#include <iostream>
#include <chrono>

int main() {
    struct Callbacks {

    };

    HMODULE Dynsec = LoadLibraryA("Client.dll");
    if (Dynsec) {
        printf("Dynsec client: %llx\n", Dynsec);
        FARPROC Initialize = GetProcAddress(Dynsec, "?InitializeClient@@YAXPEAX@Z");
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