#pragma once

#include <utility>

template <typename Fn>
class ScopeExit
{
public:
	template <typename FnT>
	ScopeExit(FnT&& fn) : _fn(std::forward<Fn>(fn)) {}
	ScopeExit(ScopeExit&&) noexcept = default;

	~ScopeExit()
	{
		_fn();
	}

private:
	Fn _fn;
};

template <typename Fn>
ScopeExit<Fn> onScopeExit(Fn&& fn)
{
	return { std::forward<Fn>(fn) };
}

#define ON_SCOPE_EXIT(tag, body) \
	auto onScopeExit_##tag = onScopeExit([&]() { \
			body; \
		});

#define ON_SCOPE_EXIT_CLASS(tag, body) \
	auto onScopeExit_##tag = onScopeExit([&, this]() { \
			body; \
		});
