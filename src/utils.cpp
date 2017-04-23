#include <iomanip>
#include <sstream>

#include "utils.h"

std::string bytesToHexString(const std::uint8_t* data, std::size_t size)
{
	std::ostringstream writer;
	for (auto itr = data; itr != data + size; ++itr)
	{
		writer << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(*itr);
	}

	return writer.str();
}
