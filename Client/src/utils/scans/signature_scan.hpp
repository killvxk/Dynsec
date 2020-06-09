#pragma once
#include "stdafx.hpp"

namespace Utils::Scans {
	uint64_t PatternScan(uint64_t Start, uint64_t End, const char* Pattern);
	uint64_t PatternScanExternalProcess(HANDLE Process, uint64_t Start, uint64_t End, const char* Pattern);
}