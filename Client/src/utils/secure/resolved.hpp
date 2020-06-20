#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
	class Resolved {
	public:
		bool Initialize();

		BOOL RtlFlushSecureMemoryCache(PVOID MemoryCache, SIZE_T MemoryLength = 0);
	private:
		enum eFunctions {
			_RtlFlushSecureMemoryCache
		};

		std::unordered_map<eFunctions, uint64_t> m_Functions;
		std::unordered_map<eFunctions, std::mutex> m_Mutexs;
	};

	Resolved* GetResolved();
}