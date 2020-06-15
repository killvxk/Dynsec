#pragma once
#include "stdafx.hpp"

namespace Dynsec::Routines {
	void MemoryScanRoutine(LPVOID lpParam);
	void ExploitableModuleScanRoutine(LPVOID lpParam);
	void NTAPI ThreadLocalStorageCallback(PVOID DllHandle, DWORD dwReason, PVOID);
}