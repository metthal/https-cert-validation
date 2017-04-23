#pragma once

#include <string>

#include "error.h"

class InvalidUriError : public Error
{
public:
	InvalidUriError() noexcept : Error("Invalid URI.") {}
};

class UriParser
{
public:
	UriParser(const std::string& uri);

	const std::string& getProtocol() const;
	const std::string& getHostname() const;
	const std::string& getResource() const;

private:
	void parse(const std::string& uri);

	std::string _protocol;
	std::string _hostname;
	std::string _resource;
};
