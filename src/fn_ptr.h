#pragma once

#include <functional>

template <typename Tag, typename Ret, typename... Args>
struct FnPtr
{
	using FunctionType = std::function<Ret(Args...)>;
	using PtrType = Ret(*)(Args...);

	static Ret invoke(Args... args)
	{
		return instance().function(std::forward<Args>(args)...);
	}

	static PtrType pointer()
	{
		return &invoke;
	}

	static FnPtr<Tag, Ret, Args...>& instance()
	{
		static FnPtr<Tag, Ret, Args...> inst;
		return inst;
	}

	FunctionType function;
};

template <typename Tag, typename Ret, typename... Args>
FnPtr<Tag, Ret, Args...>& makeFnPtr(const std::function<Ret(Args...)>& fn)
{
	auto& fnPtr = FnPtr<Tag, Ret, Args...>::instance();
	fnPtr.function = fn;
	return fnPtr;
}
