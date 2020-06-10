#pragma once
#include "stdafx.hpp"
#include "dynsec/types/init_types.hpp"

namespace Global::Vars {
	extern HMODULE g_ModuleHandle;
	extern std::unordered_map<HANDLE, bool> g_ProcessingSyscallCallback;
	extern Dynsec::InitTypes::GameDataInit* g_GameDataInit;
}