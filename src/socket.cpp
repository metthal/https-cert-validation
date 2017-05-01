#include "socket.h"
#include "uri.h"
#include "utils.h"

Socket::Socket(const Uri& uri, std::uint16_t port) : _uri(uri), _port(port), _bio(BIO_new(BIO_s_connect()))
{
}

Socket::~Socket()
{
	BIO_free_all(_bio);
}

BIO* Socket::getBIO() const
{
	return _bio;
}

const Uri& Socket::getUri() const
{
	return _uri;
}

void Socket::connect()
{
	auto hostname = _uri.getHostname();
	auto port = _uri.getPort();
	auto resource = _uri.getResource();
	if (_port > 0)
		port = numToStr(_port);

	BIO_set_conn_hostname(_bio, hostname.c_str());
	BIO_set_conn_port(_bio, port.c_str());

	if (BIO_do_connect(_bio) != 1)
		throw UnableToConnectError();

	onConnect();
}

void Socket::reconnect()
{
	BIO_free_all(_bio);
	_bio = BIO_new(BIO_s_connect());

	connect();
}

void Socket::send(const Span<const std::uint8_t>& data)
{
	std::size_t dataSent = 0;
	while (dataSent < data.getSize())
	{
		dataSent += write(makeSpan(data.getData() + dataSent, data.getSize() - dataSent));
	}
}

std::vector<std::uint8_t> Socket::receive(std::size_t toRead)
{
	std::vector<std::uint8_t> result;
	read(toRead, result);
	return result;
}

void Socket::onConnect()
{
}

std::size_t Socket::write(const Span<const std::uint8_t>& data)
{
	auto bytesWritten = BIO_write(_bio, data.getData(), data.getSize());
	if (bytesWritten <= 0)
		throw UnableToSendError();

	return bytesWritten;
}

std::size_t Socket::read(std::size_t toRead, std::vector<std::uint8_t>& dataRead)
{
	dataRead.clear();
	dataRead.resize(toRead);

	auto bytesRead = BIO_read(_bio, dataRead.data(), dataRead.size());
	if (bytesRead <= 0)
		throw UnableToReceiveError();

	dataRead.resize(bytesRead);
	return bytesRead;
}
