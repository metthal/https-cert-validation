#pragma once

#include <iostream>
#include <memory>

#include <boost/asio.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "certificate_verifier.h"
#include "error.h"

class UnableToResolveHostnameError : public Error
{
public:
	UnableToResolveHostnameError() noexcept : Error("Unable to resolve hostname.") {}
};

class SslHandshakeError : public Error
{
public:
	SslHandshakeError() noexcept : Error("SSL/TLS handshake failure.") {}
};

enum class SslMethod
{
	SSLv23_TLSv1x
};

template <SslMethod Method>
struct SslMethodTraits
{
};

template <>
struct SslMethodTraits<SslMethod::SSLv23_TLSv1x>
{
	using InitFnType = decltype(&SSLv23_method);

	constexpr static const InitFnType initFn = &SSLv23_method;
};

template <SslMethod Method>
class SslSocket
{
	using SslType = std::unique_ptr<SSL, decltype(&SSL_free)>;
	using SslContextType = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

public:
	SslSocket(const std::string& hostname, std::uint16_t port) : _hostname(hostname), _port(port), _ioService(), _socket(_ioService),
		_implTemplate(SSL_CTX_new(SslMethodTraits<Method>::initFn()), &SSL_CTX_free), _impl(nullptr, &SSL_free), _verifier(nullptr) {}

	void useTrustStore(const std::string& store)
	{
		SSL_CTX_load_verify_locations(_implTemplate.get(), store.c_str(), nullptr);
	}

	void setCertificateVerifier(BaseCertificateVerifier* verifier)
	{
		_verifier = verifier;
	}

	void connect()
	{
		auto endpoint = resolveHostname();
		_socket.connect(endpoint);

		_impl.reset(SSL_new(_implTemplate.get()));
		SSL_set_tlsext_host_name(_impl.get(), _hostname.c_str());
		SSL_set_fd(_impl.get(), _socket.native_handle());

		if (_verifier)
			SSL_set_verify(_impl.get(), SSL_VERIFY_PEER, _verifier->getCallbackPtr());

		auto err = SSL_connect(_impl.get());
		if (err <= 0)
		{
			std::cerr << SSL_get_error(_impl.get(), err) << std::endl;
			int sslError;
			while ((sslError = ERR_get_error()) != 0)
				std::cerr << ERR_error_string(sslError, nullptr) << std::endl;
			throw SslHandshakeError();
		}

		std::cout << "\tSSL version: " << SSL_get_version(_impl.get()) << std::endl;
		std::cout << "\tSSL cipher: " << SSL_get_cipher(_impl.get()) << std::endl;
	}

protected:
	boost::asio::ip::tcp::endpoint resolveHostname()
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

private:
	std::string _hostname;
	std::uint16_t _port;
	boost::asio::io_service _ioService;
	boost::asio::ip::tcp::socket _socket;
	SslContextType _implTemplate;
	SslType _impl;
	BaseCertificateVerifier* _verifier;
};
