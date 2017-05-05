#include "http_client.h"
#include "ssl_socket.h"

HttpClient::HttpClient(const Uri& uri, std::uint16_t port) : _socket()
{
	if (uri.getProtocol() == "https")
		_socket = std::make_unique<SslSocket>(uri, port);
	else
		_socket = std::make_unique<Socket>(uri, port);

	_socket->connect();
}


std::string HttpClient::request(const std::string& resource)
{
	std::ostringstream requestWriter;
	requestWriter << "GET " << resource << " HTTP/1.1\r\n"
		<< "Host: " << _socket->getUri().getHostname() << "\r\n"
		<< "\r\n";
	auto requestStr = requestWriter.str();
	_socket->send(makeSpan(reinterpret_cast<const std::uint8_t*>(requestStr.data()), requestStr.size()));

	std::stringstream responseWriter;

	const std::size_t blockSize = 1024;
	std::vector<std::uint8_t> buffer(blockSize);
	while (buffer.size() == blockSize)
	{
		buffer = _socket->receive(blockSize);
		responseWriter << std::string{buffer.data(), buffer.data() + buffer.size()};
	}

	// Skip all headers and find empty line which marks the end of them
	std::string line;
	while (std::getline(responseWriter, line) && trim(line) != "");

	std::string response;
	char byte;
	while (responseWriter.read(&byte, 1))
		response += byte;

	return response;
}
