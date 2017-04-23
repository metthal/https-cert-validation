#include <regex>

#include "uri_parser.h"

UriParser::UriParser(const std::string& uri) : _protocol(), _hostname(), _resource()
{
	parse(uri);
}

const std::string& UriParser::getProtocol() const
{
	return _protocol;
}

const std::string& UriParser::getHostname() const
{
	return _hostname;
}

const std::string& UriParser::getResource() const
{
	return _resource;
}

void UriParser::parse(const std::string& uri)
{
	static std::regex uriRegex(R"(^(([^:]+)://)?([^/]+)(/(.*)?)?$)", std::regex::ECMAScript);

	std::smatch matches;
	if (!std::regex_match(uri, matches, uriRegex))
		throw InvalidUriError();

	if (matches[2].matched)
		_protocol = matches[2].str();

	_hostname = matches[3].str();

	if (matches[4].matched)
		_resource = matches[4].str();
}
