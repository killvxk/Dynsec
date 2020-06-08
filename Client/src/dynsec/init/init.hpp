#pragma once
#include "stdafx.hpp"
#include "dynsec/types/init_types.hpp"

namespace Dynsec::Init {
	void Initialize();
	void InitializeClient(Dynsec::InitTypes::Callbacks* pCallbacks);
}