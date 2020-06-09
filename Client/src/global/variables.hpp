#pragma once
#include "stdafx.hpp"

namespace Global::Vars {
	extern HMODULE g_ModuleHandle;
	extern std::unordered_map<HANDLE, bool> g_ProcessingSyscallCallback;
}