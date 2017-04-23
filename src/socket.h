#pragma once

#include <boost/asio.hpp>

#include "error.h"
#include "span.h"

class UnableToResolveHostnameError : public Error
{
public:
	UnableToResolveHostnameError() noexcept : Error("Unable to resolve hostname.") {}
};

class UnableToConnectError : public Error
{
public:
	UnableToConnectError() noexcept : Error("Unable to connect to the remote endpoint.") {}
};

class UnableToSendError : public Error
{
public:
	UnableToSendError() noexcept : Error("Unable to send data.") {}
};

class UnableToReceiveError : public Error
{
public:
	UnableToReceiveError() noexcept : Error("Unable to receive data.") {}
};

class Socket
{
public:
	Socket(const std::string& hostname, std::uint16_t port);
	virtual ~Socket() = default;

	const std::string& getHostname() const;

	void connect();
	void send(const Span<const std::uint8_t>& data);
	std::vector<std::uint8_t> receive(std::size_t toRead);

protected:
	virtual void onConnect();
	virtual std::size_t write(const Span<const std::uint8_t>& data);
	virtual std::size_t read(std::size_t toRead, std::vector<std::uint8_t>& dataRead);
	boost::asio::ip::tcp::endpoint resolveHostname();

	std::string _hostname;
	std::uint16_t _port;
	boost::asio::io_service _ioService;
	boost::asio::ip::tcp::socket _socket;
};
