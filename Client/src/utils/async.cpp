#include "async.hpp"
#include <future>

namespace Utils::Async {
	void AsyncRoutine::Begin(void* Param, std::function<void(void*)> Callback) {
		AsyncContext* ctx = new AsyncContext();
		ctx->m_Param = Param;
		ctx->m_Callback = Callback;

		std::async(std::launch::deferred, [&] {
			return RunAsync(ctx);
		}).wait();
	}
}