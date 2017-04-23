#pragma once

#include <memory>
#include <string>

std::string trim(std::string str);
std::string bytesToHexString(const std::uint8_t* data, std::size_t size);

template <typename T, typename Deleter>
decltype(auto) makeUnique(T* ptr, Deleter deleter)
{
	return std::unique_ptr<T, Deleter>(ptr, deleter);
}

template <typename T, typename Deleter>
decltype(auto) makeShared(T* ptr, Deleter deleter)
{
	return std::shared_ptr<T>(ptr, deleter);
}
