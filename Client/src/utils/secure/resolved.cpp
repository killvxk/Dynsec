#include "resolved.hpp"
#include "utils/caller.hpp"
#include "utils/secure/pointers.hpp"
#include "utils/secure/module.hpp"

namespace Utils::Secure {
	bool Resolved::Initialize() {
		// TODO: Integrity check each resolve

		auto Ntdll = Utils::Secure::GetModuleHandle(L"ntdll.dll");
		if (!Ntdll) { return false; }

		auto Iphl = Utils::Secure::GetModuleHandle(L"iphlpapi.dll");
		if (!Iphl) { return false; }

		m_Functions[_RtlFlushSecureMemoryCache] = (uint64_t)Utils::Secure::GetProcAddress(Ntdll, "RtlFlushSecureMemoryCache");

		for (auto& Functions : m_Functions) {
			if (!Functions.second) return false;
			Functions.second = (uint64_t)EncodePtr((void*)Functions.second);
		}

		return true;
	}

	BOOL Resolved::RtlFlushSecureMemoryCache(PVOID MemoryCache, SIZE_T MemoryLength) {
		std::unique_lock<std::mutex> l(m_Mutexs[_RtlFlushSecureMemoryCache]);
		return Utils::Caller::Call<BOOL>((uint64_t)DecodePtr((void*)m_Functions[_RtlFlushSecureMemoryCache]), MemoryCache, MemoryLength);
	}

	Resolved* GetResolved() {
		static Resolved Instance;
		return &Instance;
	}
}