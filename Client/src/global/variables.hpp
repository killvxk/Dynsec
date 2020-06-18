#pragma once
#include "stdafx.hpp"
#include "dynsec/types/init_types.hpp"
#include "dynsec/types/routine_types.hpp"

namespace Global::Vars {
	extern HMODULE g_ModuleHandle;
	extern std::unordered_map<HANDLE, bool> g_ProcessingSyscallCallback;
	extern Dynsec::InitTypes::GameDataInit* g_GameDataInit;
	extern std::vector<Dynsec::RoutineTypes::MemorySignature> g_MemorySignatures;
	extern std::vector<Dynsec::RoutineTypes::ThreadEntrySignature> g_ThreadEntrySignatures;
	extern std::vector<std::string> g_WindowTitleSignatures;
}