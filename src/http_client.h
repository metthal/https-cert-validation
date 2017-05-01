#pragma once

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "socket.h"
#include "span.h"
#include "uri.h"
#include "utils.h"

class HttpClient
{
public:
	HttpClient(const Uri& uri, std::uint16_t port = 0);

	std::string request(const std::string& resource);

private:
	std::unique_ptr<Socket> _socket;
};
