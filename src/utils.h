#pragma once

#include <memory>
#include <sstream>
#include <string>

template <typename T, typename Manipulator = decltype(std::dec)>
std::string numToStr(T value, Manipulator&& manip = std::dec)
{
	std::ostringstream ss;
	ss << manip << value;
	return ss.str();
}

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
