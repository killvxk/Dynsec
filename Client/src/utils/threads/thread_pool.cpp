#include "thread_pool.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/secure/syscall.hpp"

namespace Utils::Threads {
	ThreadContext* ThreadPool::CreateThread(uint32_t Identifier, std::function<void(void*)> ThreadCallback, void* Param) {
		ThreadContext* Context = new ThreadContext();
		Context->m_Identifier = Identifier;
		Context->m_ThreadCallback = ThreadCallback;
		Context->m_ThreadParam = Param;

		Context->m_Handle = Utils::Secure::CreateThread(0, [] (LPVOID lpParam) -> DWORD {
			ThreadContext* LocalContext = (ThreadContext*)lpParam;

			while (LocalContext->m_Running) {
				if (!LocalContext->m_Paused) {
					LocalContext->m_ThreadCallback(LocalContext->m_ThreadParam);
				}
			}

			delete LocalContext;
			return 0;
		}, Context, 0, 0);

		printf("Created thread: %llx\n", Context->m_Handle);

		m_Threads.push_back(Context);

		// ThreadHideFromDebugger
		Utils::Secure::GetSyscalls()->NtSetInformationThread(Context->m_Handle, 17, 0, 0);

		return Context;
	}

	void ThreadPool::PauseThread(uint32_t Identifier) {
		auto Vit = std::find_if(begin(m_Threads), end(m_Threads), [=] (ThreadContext* Context) {
			return Context->m_Identifier == Identifier;
		});

		if (Vit != end(m_Threads)) {
			(*Vit)->m_Paused = false;
		}
	}

	void ThreadPool::ResumeThread(uint32_t Identifier) {
		auto Vit = std::find_if(begin(m_Threads), end(m_Threads), [=] (ThreadContext* Context) {
			return Context->m_Identifier == Identifier;
		});

		if (Vit != end(m_Threads)) {
			(*Vit)->m_Paused = true;
		}
	}

	void ThreadPool::CloseThread(uint32_t Identifier) {
		auto Vit = std::find_if(begin(m_Threads), end(m_Threads), [=] (ThreadContext* Context) {
			return Context->m_Identifier == Identifier;
		});

		if (Vit != end(m_Threads)) {
			(*Vit)->m_Running = false;
		}
	}

	ThreadPool* GetThreadPool() {
		static ThreadPool Instance;
		return &Instance;
	}
}