#pragma once

#include <openssl/bio.h>

#include "error.h"
#include "span.h"
#include "uri.h"

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
	Socket(const Uri& uri, std::uint16_t port = 0);
	virtual ~Socket();

	BIO* getBIO() const;
	const Uri& getUri() const;

	void connect();
	void reconnect();
	void send(const Span<const std::uint8_t>& data);
	std::vector<std::uint8_t> receive(std::size_t toRead);

protected:
	virtual void onConnect();
	virtual std::size_t write(const Span<const std::uint8_t>& data);
	virtual std::size_t read(std::size_t toRead, std::vector<std::uint8_t>& dataRead);

	Uri _uri;
	std::uint16_t _port;
	BIO* _bio;
};
