#pragma once

#include <cstddef>
#include <vector>

#include "error.h"

class PositionOutOfBoundsError : public Error
{
public:
	PositionOutOfBoundsError() noexcept : Error("Position is out of span bounds.") {}
};

template <typename T>
class Span
{
public:
	Span(T* data, std::size_t size) noexcept : _data(data), _size(size) {}
	Span(const Span&) noexcept = default;
	Span(Span&&) noexcept = default;

	Span& operator=(const Span&) noexcept = default;
	Span& operator=(Span&&) noexcept = default;

	T* getData() noexcept { return _data; }
	const T* getData() const noexcept { return _data; }
	std::size_t getSize() const noexcept { return _size; }

	std::vector<T> copyToVector(std::size_t startPos = 0) const
	{
		return copyToVector(startPos, _size - startPos);
	}

	std::vector<T> copyToVector(std::size_t startPos, std::size_t size) const
	{
		if (startPos >= _size || startPos + size > _size)
			throw PositionOutOfBoundsError();

		return std::vector<T>(_data + startPos, _data + startPos + size);
	}

private:
	T* _data;
	std::size_t _size;
};

template <typename T>
auto makeSpan(T* data, std::size_t size)
{
	return Span<T>{ data, size };
}
