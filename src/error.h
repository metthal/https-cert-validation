#pragma once

#include <exception>
#include <string>

class Error : public std::exception
{
public:
	Error(const std::string& message) noexcept : _message(message) {}
	Error(const Error& rhs) noexcept : _message(rhs._message) {}
	~Error() = default;

	Error& operator=(const Error& rhs) noexcept
	{
		_message = rhs._message;
		return *this;
	}

	virtual const char* what() const noexcept override
	{
		return _message.c_str();
	}

private:
	std::string _message;
};
