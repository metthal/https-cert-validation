#pragma once

#include <memory>
#include <sstream>
#include <string>
#include <vector>

std::string trim(std::string str);
std::string bytesToHexString(const std::uint8_t* data, std::size_t size);
bool containsCaseInsensitive(const std::string& str, const std::string& what);
bool isSuffix(const std::string& str, const std::string& prefix);
std::vector<std::string> split(const std::string& str, const std::string& delim);

template <typename T, typename Manipulator = decltype(std::dec)>
std::string numToStr(T value, Manipulator&& manip = std::dec)
{
	std::ostringstream ss;
	ss << manip << value;
	return ss.str();
}

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

template <typename It>
std::string join(It first, It last, const std::string& delim)
{
	std::string result;
	for (auto itr = first; itr != last; ++itr)
	{
		if (!result.empty())
			result += delim;

		result += *itr;
	}

	return result;
}

template <typename Container, typename T>
void insertOrderedUnique(Container& container, T&& value)
{
	auto itr = std::lower_bound(container.begin(), container.end(), value);
	if (itr == container.end() || *itr != value)
		container.insert(itr, std::forward<T>(value));
}
