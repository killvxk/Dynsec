#pragma once
#include "stdafx.hpp"
#include "utils/structs.hpp"
#include "utils/secure/module.hpp"

namespace Dynsec::Init {
	class TLSManager {
	public:
		bool RegisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback);
		// static bool UnregisterCallback(HMODULE module, PIMAGE_TLS_CALLBACK pCallback);

	private:
		bool m_IsCustomCallbackArray = false;
		void* m_pLdrpTlsList = nullptr;
		void* m_pInLoadOrderModuleList = nullptr;

		PTLS_ENTRY m_LdrpTlsList = nullptr;
		PLIST_ENTRY m_InLoadOrderModuleList = nullptr;

		void Setup();
		PLDR_DATA_TABLE_ENTRY FindLdrTableForModule(HMODULE hModule);
		PTLS_ENTRY FindTlsEntryForModule(HMODULE hModule);
		SIZE_T GetTlsCallbackCount(PTLS_ENTRY entry);
	};

	TLSManager* GetTLSManager();
}