#pragma once
#include "stdafx.hpp"
#include "dynsec/types/init_types.hpp"

namespace Dynsec::Init {
	void Initialize(LPVOID lpParam);
	void InitializeClient(Dynsec::InitTypes::GameDataInit* InitData);
}