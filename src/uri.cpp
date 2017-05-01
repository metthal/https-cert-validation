#include <regex>

#include "uri.h"

Uri::Uri(const std::string& uri) : _protocol(), _hostname(), _port(), _resource()
{
	parse(uri);
}

const std::string& Uri::getProtocol() const
{
	return _protocol;
}

const std::string& Uri::getHostname() const
{
	return _hostname;
}

const std::string& Uri::getPort() const
{
	return _port;
}

const std::string& Uri::getResource() const
{
	return _resource;
}

void Uri::parse(const std::string& uri)
{
	static std::regex uriRegex(R"(^(([^:]+)://)?([^:/]+)(:([0-9]+))?(/(.*)?)?$)", std::regex::ECMAScript);

	std::smatch matches;
	if (!std::regex_match(uri, matches, uriRegex))
		throw InvalidUriError();

	if (matches[2].matched)
		_protocol = matches[2].str();

	_hostname = matches[3].str();

	if (matches[5].matched)
		_port = matches[5].str();
	else if (_protocol == "http")
		_port = "80";
	else if (_protocol == "https")
		_port = "443";

	if (matches[6].matched)
		_resource = matches[6].str();
}
