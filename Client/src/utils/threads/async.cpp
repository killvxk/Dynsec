#include "async.hpp"
#include <future>

namespace Utils::Async {
	void AsyncRoutine::Begin(void* Param, std::function<void(void*)> Callback) {
		AsyncContext* ctx = new AsyncContext();
		ctx->m_Param = Param;
		ctx->m_Callback = Callback;

		auto f = std::async(std::launch::async, [&] {
			return RunAsync(ctx);
		});
	}
}