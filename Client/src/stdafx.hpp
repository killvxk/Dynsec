#ifndef PCH_H
#define PCH_H

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <stdlib.h>
#include <fstream>
#include <stdio.h>
#include <intrin.h>

#define EncodePtr Utils::Secure::GetPointers()->EncodePointer
#define DecodePtr Utils::Secure::GetPointers()->DecodePointer

#undef GetCurrentProcess
#define GetCurrentProcess() (HANDLE)-1

#ifdef _WIN64
#define ProcessEnvironmentBlock ((PEB*)__readgsqword(0x60))
#else
#include "utils/structs.hpp"

inline PEB* GetProcessEnvironmentBlockAsm() {
	PEB* peb = nullptr;
	__asm {
		mov eax, fs: [0x30]
		mov peb, eax
	}

	return peb;
}

#define ProcessEnvironmentBlock GetProcessEnvironmentBlockAsm()
#endif

#endif