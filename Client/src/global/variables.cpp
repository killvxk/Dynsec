#include "variables.hpp"

namespace Global::Vars {
	HMODULE g_ModuleHandle;
	std::unordered_map<HANDLE, bool> g_ProcessingSyscallCallback;
	Dynsec::InitTypes::GameDataInit* g_GameDataInit;
}