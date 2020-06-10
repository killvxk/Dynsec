#pragma once
#include "stdafx.hpp"

namespace Utils::Threads {
	struct ThreadContext {
		uint32_t m_Identifier;
		HANDLE m_Handle;
		bool m_Running = true;
		bool m_Paused;
		void* m_ThreadParam;
		std::function<void(void*)> m_ThreadCallback;
	};

	class ThreadPool {
	public:
		ThreadContext* CreateThread(uint32_t Identifier, std::function<void(void*)> ThreadCallback, void* Param = nullptr);
		void PauseThread(uint32_t Identifier);
		void ResumeThread(uint32_t Identifier);
		void CloseThread(uint32_t Identifier);

		std::vector<ThreadContext*> GetThreads() { return m_Threads; }
	private:
		std::vector<ThreadContext*> m_Threads;
	};

	ThreadPool* GetThreadPool();
}