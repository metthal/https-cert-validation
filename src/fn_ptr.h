#pragma once

#include <functional>

template <std::size_t Id, typename Tag, typename Ret, typename... Args>
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

	static FnPtr<Id, Tag, Ret, Args...>& instance()
	{
		static FnPtr<Id, Tag, Ret, Args...> inst;
		return inst;
	}

	FunctionType function;
};

template <std::size_t Id, typename Tag, typename Ret, typename... Args>
FnPtr<Id, Tag, Ret, Args...>& makeFnPtr(const std::function<Ret(Args...)>& fn)
{
	auto& fnPtr = FnPtr<Id, Tag, Ret, Args...>::instance();
	fnPtr.function = fn;
	return fnPtr;
}
