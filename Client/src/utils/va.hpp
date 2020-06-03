#pragma once
#include "stdafx.hpp"

namespace Utils::VA {
	const char* VA(const char* fmt, ...);
	const wchar_t* VAW(const char* fmt, ...);
	const char* VABuffer(char* buffer, std::size_t size, const char* fmt, ...);
}