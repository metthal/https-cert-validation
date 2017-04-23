#pragma once

#include <boost/asio.hpp>

#include "error.h"

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

class Socket
{
public:
	Socket(const std::string& hostname, std::uint16_t port);
	virtual ~Socket() = default;

	void connect();

protected:
	virtual void onConnect();
	boost::asio::ip::tcp::endpoint resolveHostname();

	std::string _hostname;
	std::uint16_t _port;
	boost::asio::io_service _ioService;
	boost::asio::ip::tcp::socket _socket;
};
