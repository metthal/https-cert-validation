#include <iomanip>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>

#include "utils.h"

std::string trim(std::string str)
{
	boost::trim(str);
	return str;
}

std::string bytesToHexString(const std::uint8_t* data, std::size_t size)
{
	std::ostringstream writer;
	for (auto itr = data; itr != data + size; ++itr)
	{
		writer << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(*itr);
	}

	return writer.str();
}

bool containsCaseInsensitive(const std::string& str, const std::string& what)
{
	using StringRange = boost::iterator_range<std::string::const_iterator>;
	auto strRange = StringRange{ str.begin(), str.end() };
	auto whatRange = StringRange{ what.begin(), what.end() };
	return boost::ifind_first(strRange, whatRange);
}

bool isSuffix(const std::string& suffix, const std::string& str)
{
	auto pos = str.rfind(suffix);
	if (pos == std::string::npos)
		return false;

	return pos + suffix.length() == str.length();
}

std::vector<std::string> split(const std::string& str, const std::string& delim)
{
	boost::char_separator<char> sep(delim.c_str());
	boost::tokenizer<decltype(sep)> tokens(str, sep);
	return std::vector<std::string>(tokens.begin(), tokens.end());
}
