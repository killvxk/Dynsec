#pragma once
#include "stdafx.hpp"

namespace Utils::Async {
	struct AsyncContext {
		void* m_Param;
		std::function<void(void*)> m_Callback;
	};

	class AsyncRoutine {
	public:
		// the begin routine to start the thread
		void Begin(void* Param, std::function<void(void*)> Callback);
	protected:
		// RunAsync gets access to the params
		virtual void RunAsync(AsyncContext* Param) = 0;
	};
}