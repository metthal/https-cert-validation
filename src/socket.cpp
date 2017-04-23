#include "socket.h"

Socket::Socket(const std::string& hostname, std::uint16_t port) : _hostname(hostname), _port(port), _ioService(), _socket(_ioService)
{
}

void Socket::connect()
{
	boost::system::error_code errorCode;
	auto endpoint = resolveHostname();
	_socket.connect(endpoint, errorCode);

	if (errorCode)
		throw UnableToConnectError();

	onConnect();
}

void Socket::onConnect()
{
}

boost::asio::ip::tcp::endpoint Socket::resolveHostname()
{
	boost::system::error_code errorCode;
	auto address = boost::asio::ip::address::from_string(_hostname, errorCode);
	if (!errorCode)
		return { address, _port };

	// No IP address parsable out of hostname, try to use DNS
	boost::asio::ip::tcp::resolver dnsResolver(_ioService);
	boost::asio::ip::tcp::resolver::query dnsQuery(_hostname, "");

	std::vector<boost::asio::ip::tcp::endpoint> possibleEndpoints;
	for (auto itr = dnsResolver.resolve(dnsQuery, errorCode), end = boost::asio::ip::tcp::resolver::iterator{}; !errorCode && itr != end; ++itr)
		possibleEndpoints.push_back(*itr);

	if (errorCode || possibleEndpoints.empty())
		throw UnableToResolveHostnameError();

	// Pick IPv4 over everything other
	auto itr = std::find_if(possibleEndpoints.begin(), possibleEndpoints.end(),
			[](const boost::asio::ip::tcp::endpoint& endpoint) {
				return endpoint.address().is_v4();
			});

	boost::asio::ip::tcp::endpoint result;
	if (itr != possibleEndpoints.end())
		result = *itr;
	else // Otherwise pick the first one available
		result = possibleEndpoints.front();

	return { result.address(), _port };
}
