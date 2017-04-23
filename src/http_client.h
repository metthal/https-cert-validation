#pragma once

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "span.h"
#include "utils.h"

template <typename SocketT>
class HttpClient
{
public:
	HttpClient(const std::string& hostname, std::uint16_t port) : _socket(hostname, port) {}

	void connect()
	{
		_socket.connect();
	}

	std::string request(const std::string& resource)
	{
		std::ostringstream requestWriter;
		requestWriter << "GET " << resource << " HTTP/1.1\r\n"
			<< "Host: " << _socket.getHostname() << "\r\n"
			<< "\r\n";
		auto requestStr = requestWriter.str();
		_socket.send(makeSpan(reinterpret_cast<const std::uint8_t*>(requestStr.data()), requestStr.size()));

		std::stringstream responseWriter;

		const std::size_t blockSize = 1024;
		std::vector<std::uint8_t> buffer(blockSize);
		while (buffer.size() == blockSize)
		{
			buffer = _socket.receive(blockSize);
			responseWriter << std::string{buffer.data(), buffer.data() + buffer.size()};
		}

		std::string line;
		while (std::getline(responseWriter, line) && trim(line) != "");

		std::string response;
		char byte;
		while (responseWriter.read(&byte, 1))
			response += byte;

		return response;
	}

private:
	SocketT _socket;
};
