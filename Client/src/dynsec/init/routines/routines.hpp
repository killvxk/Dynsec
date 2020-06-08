#pragma once
#include "stdafx.hpp"

namespace Dynsec::Routines {
	void NTAPI ThreadLocalStorageCallback(PVOID DllHandle, DWORD dwReason, PVOID);
}