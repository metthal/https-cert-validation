#pragma once

#include <memory>

#include <openssl/ssl.h>

#include "certificate.h"
#include "socket.h"
#include "utils.h"

class SslHandshakeError : public Error
{
public:
	SslHandshakeError() noexcept : Error("SSL/TLS handshake failure.") {}
};

class SslSocket : public Socket
{
	using SslContextType = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

public:
	SslSocket(const Uri& uri, std::uint16_t port = 0);

	std::vector<Certificate> getCertificateChain() const;
	std::string getUsedTlsVersion() const;
	std::string getUsedCipher() const;

	X509* getServerCertificateX509() const;
	STACK_OF(X509)* getCertificateChainX509() const;
	X509_STORE* getTrustedStoreX509() const;

	void useDefaultTrustStore();
	void useTrustStore(const std::string& store);

protected:
	virtual void onConnect() override;

private:
	SslContextType _implTemplate;
	SSL* _impl;
	std::size_t _connectionTry;
};
