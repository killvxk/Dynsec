#include "tls_manager.hpp"
#include "global/variables.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"

namespace Dynsec::Init {
	void TLSManager::Setup() {
		// TODO: Sig scan these
		m_pInLoadOrderModuleList = (void*)((uintptr_t)Utils::Secure::GetModuleHandle(L"ntdll.dll") + 0x1653D0);
		m_pLdrpTlsList = (void*)((uintptr_t)Utils::Secure::GetModuleHandle(L"ntdll.dll") + 0x15F520);

		m_LdrpTlsList = *(PTLS_ENTRY*)m_pLdrpTlsList;
		m_pInLoadOrderModuleList = *(PLIST_ENTRY*)m_pInLoadOrderModuleList;
	}

	PLDR_DATA_TABLE_ENTRY TLSManager::FindLdrTableForModule(HMODULE hModule) {
		for (auto it = m_InLoadOrderModuleList; it != m_pInLoadOrderModuleList; it = *(PLIST_ENTRY*)it) {
			PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)it;

			if (entry->DllBase == hModule) {
				return entry;
			}
		}

		return nullptr;
	}

	PTLS_ENTRY TLSManager::FindTlsEntryForModule(HMODULE hModule) {
		for (_TLS_ENTRY* it = m_LdrpTlsList; it != m_pLdrpTlsList; it = (_TLS_ENTRY*)it->TlsEntryLinks.Flink) {
			if (!it) {
				continue;
			}

			if (!it->ModuleEntry) {
				continue;
			}

			if (it->ModuleEntry->DllBase == hModule) {
				return it;
			}
		}

		return nullptr;
	}

	SIZE_T TLSManager::GetTlsCallbackCount(PTLS_ENTRY entry) {
		PIMAGE_TLS_CALLBACK* pCallbackList = (PIMAGE_TLS_CALLBACK*)entry->TlsDirectory.AddressOfCallBacks;

		if (!pCallbackList) {
			return 0;
		}

		int count = 0;

		PIMAGE_TLS_CALLBACK currentCallback = *pCallbackList;
		while (true) {
			currentCallback = *pCallbackList;

			if (!*pCallbackList) {
				break;
			}

			++count;
			++pCallbackList;
		}

		return count;
	}

	SIZE_T TLSManager::FindCallbackIndex(PTLS_ENTRY entry, PIMAGE_TLS_CALLBACK callback) {
		PIMAGE_TLS_CALLBACK* pCallbackList = (PIMAGE_TLS_CALLBACK*)entry->TlsDirectory.AddressOfCallBacks;

		if (!pCallbackList) {
			return 0;
		}

		int count = 0;

		PIMAGE_TLS_CALLBACK currentCallback = *pCallbackList;
		while (true) {
			currentCallback = *pCallbackList;

			if (!*pCallbackList) 
				break;
			

			if (currentCallback == callback)
				return count+1;

			++count;
			++pCallbackList;
		}

		return count;
	}

	bool TLSManager::RegisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback) {
		if (!m_IsCustomCallbackArray) {
			Setup();
		}

		PTLS_ENTRY entry = FindTlsEntryForModule(module);
		if (entry == nullptr) {
			return false;
		}

		SIZE_T nCallbacks = GetTlsCallbackCount(entry);

		uintptr_t* callbacksMemory = new uintptr_t[nCallbacks + 2] {};
		memcpy(callbacksMemory, (void*)entry->TlsDirectory.AddressOfCallBacks, nCallbacks * sizeof(uintptr_t));

		if (m_IsCustomCallbackArray) {
			delete (void*)entry->TlsDirectory.AddressOfCallBacks;
		}

		callbacksMemory[nCallbacks] = (uintptr_t)pCallback;
		callbacksMemory[nCallbacks + 1] = 0;

		entry->TlsDirectory.AddressOfCallBacks = (uintptr_t)callbacksMemory;
		m_IsCustomCallbackArray = true;

		return true;
	}

	bool TLSManager::UnregisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback) {
		if (!m_IsCustomCallbackArray) {
			Setup();
		}

		PTLS_ENTRY entry = FindTlsEntryForModule(module);
		if (entry == nullptr) {
			return false;
		}

		SIZE_T nCallbacks = GetTlsCallbackCount(entry);
		if (nCallbacks <= 0) {
			return false;
		}

		if (nCallbacks == 1) {
			// Check if it's actually the callback we want to unregister
			if (*(void**)entry->TlsDirectory.AddressOfCallBacks != pCallback) {
				return false;
			}

			entry->TlsDirectory.AddressOfCallBacks = 0;
			return true;
		}

		uintptr_t** callbacks = *(uintptr_t***)entry->TlsDirectory.AddressOfCallBacks;

		SIZE_T iCallbackIndex = FindCallbackIndex(entry, pCallback);

		// We need an array of nCallbacks size because we need to keep in mind that 
		// the array needs the last item to be 0. (last item(0) not counted in nCallbacks)
		uintptr_t* callbacksMemory = new uintptr_t[nCallbacks]{};

		if (iCallbackIndex == 1) {
			memcpy(callbacksMemory, 
				(void*)(entry->TlsDirectory.AddressOfCallBacks + sizeof(uintptr_t)), 
				(nCallbacks - 1) * sizeof(uintptr_t));
		} else if (iCallbackIndex == nCallbacks) {
			memcpy(callbacksMemory, 
				(void*)entry->TlsDirectory.AddressOfCallBacks, 
				(nCallbacks - 1) * sizeof(uintptr_t));
		} else {
			memcpy(callbacksMemory, 
				(void*)entry->TlsDirectory.AddressOfCallBacks, 
				(iCallbackIndex - 1) * sizeof(uintptr_t));

			memcpy(callbacksMemory + (iCallbackIndex - 1), 
				(uintptr_t*)(entry->TlsDirectory.AddressOfCallBacks) + iCallbackIndex, 
				(nCallbacks - iCallbackIndex) * sizeof(uintptr_t));
		}

		if (m_IsCustomCallbackArray) {
			delete (void*)entry->TlsDirectory.AddressOfCallBacks;
		}

		callbacksMemory[nCallbacks] = 0;
		entry->TlsDirectory.AddressOfCallBacks = (uintptr_t)callbacksMemory;
		m_IsCustomCallbackArray = true;

		return true;
	}

	TLSManager* GetTLSManager() {
		static TLSManager Instance;
		return &Instance;
	}
}