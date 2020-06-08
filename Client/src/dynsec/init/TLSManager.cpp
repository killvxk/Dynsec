#include "TLSManager.h"
#include "global/variables.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#undef GetModuleHandle


void TLSManager::Setup()
{
	m_pInLoadOrderModuleList = (void*)((uintptr_t)Utils::Secure::GetModuleHandle(L"ntdll.dll") + 0x1653D0);
	m_pLdrpTlsList = (void*)((uintptr_t)Utils::Secure::GetModuleHandle(L"ntdll.dll") + 0x15F520);

	m_LdrpTlsList = *(PTLS_ENTRY*)m_pLdrpTlsList;
	m_pInLoadOrderModuleList = *(PLIST_ENTRY*)m_pInLoadOrderModuleList;
}

PLDR_DATA_TABLE_ENTRY TLSManager::FindLdrTableForModule(HMODULE hModule)
{
	for (auto it = m_InLoadOrderModuleList; it != m_pInLoadOrderModuleList; it = *(PLIST_ENTRY*)it) {
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)it;

		if (entry->DllBase == hModule)
			return entry;
	}
}

PTLS_ENTRY TLSManager::FindTlsEntryForModule(HMODULE hModule)
{
	for (_TLS_ENTRY* it = m_LdrpTlsList; it != m_pLdrpTlsList; it = (_TLS_ENTRY *)it->TlsEntryLinks.Flink)
	{
		if (!it)
			continue;
		if (!it->ModuleEntry)
			continue;
		
		if (it->ModuleEntry->DllBase == hModule)
			return it;
	}
	return nullptr;
}

SIZE_T TLSManager::GetTlsCallbackCount(PTLS_ENTRY entry)
{
	PIMAGE_TLS_CALLBACK* pCallbackList = (PIMAGE_TLS_CALLBACK *)entry->TlsDirectory.AddressOfCallBacks;

	if (!pCallbackList)
		return 0;

	int count = 0;

	PIMAGE_TLS_CALLBACK currentCallback = *pCallbackList;
	while (true) {
		currentCallback = *pCallbackList;
		if (!*pCallbackList) 
			break;
		
		++count;
		++pCallbackList;

	}

	return count;
}

bool TLSManager::RegisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback)
{
	if(!m_IsCustomCallbackArray)
		Setup();
	PTLS_ENTRY entry = FindTlsEntryForModule(module);
	if (entry == nullptr)
		return false;

	SIZE_T nCallbacks = GetTlsCallbackCount(entry);

	uintptr_t* callbacksMemory = new uintptr_t[nCallbacks + 2]{};
	memcpy(callbacksMemory, (void*)entry->TlsDirectory.AddressOfCallBacks, nCallbacks * sizeof(uintptr_t));


	if (m_IsCustomCallbackArray)
		delete (void*)entry->TlsDirectory.AddressOfCallBacks;

	callbacksMemory[nCallbacks] = (uintptr_t)pCallback;
	callbacksMemory[nCallbacks+1] = 0;

	entry->TlsDirectory.AddressOfCallBacks = (uintptr_t)callbacksMemory;
	m_IsCustomCallbackArray = true;

	return true;
}

//bool TLSManager::UnregisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback)
//{
//	if (!m_IsCustomCallbackArray)
//		Setup();
//	PTLS_ENTRY entry = FindTlsEntryForModule(module);
//	if (entry == nullptr)
//		return false;
//
//	SIZE_T nCallbacks = GetTlsCallbackCount(entry);
//	if (nCallbacks <= 0)
//		return false;
//
//	if (nCallbacks == 1) {
//		// Check if it's actually the callback we want to unregister
//		if (*(void**)entry->TlsDirectory.AddressOfCallBacks != pCallback)
//			return false;
//		entry->TlsDirectory.AddressOfCallBacks = 0;
//		return true;
//	}
//
//	uintptr_t* callbacks = *(uintptr_t**)entry->TlsDirectory.AddressOfCallBacks;
//
//	int iCallbackIndex = 0;
//	for (uintptr_t* ptr = callbacks; ptr; ptr++) {
//		if (*ptr == (uintptr_t)pCallback)
//			break;
//		++iCallbackIndex;
//	}
//
//	uintptr_t* callbacksMemory = new uintptr_t[nCallbacks - 1]{};
//	memcpy(callbacksMemory, (void*)entry->TlsDirectory.AddressOfCallBacks, nCallbacks * sizeof(uintptr_t));
//
//
//	if (m_IsCustomCallbackArray)
//		delete (void*)entry->TlsDirectory.AddressOfCallBacks;
//
//	callbacksMemory[nCallbacks] = (uintptr_t)pCallback;
//	callbacksMemory[nCallbacks + 1] = 0;
//
//	entry->TlsDirectory.AddressOfCallBacks = (uintptr_t)callbacksMemory;
//	m_IsCustomCallbackArray = true;
//
//	return true;
//}


TLSManager* GetTLSManager() {
	static TLSManager Instance;
	return &Instance;
}