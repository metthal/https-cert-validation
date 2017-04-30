#pragma once

#include <memory>

#include <openssl/ssl.h>

#include "certificate_verifier.h"
#include "socket.h"
#include "utils.h"

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
class SslSocket : public Socket
{
	using SslType = std::unique_ptr<SSL, decltype(&SSL_free)>;
	using SslContextType = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

public:
	SslSocket(const std::string& hostname, std::uint16_t port);

	const Certificate& getPeerCertificate() const;
	const std::vector<Certificate>& getPeerCertificateChain() const;

	void useDefaultTrustStore();
	void useTrustStore(const std::string& store);
	void enableCrlVerification();
	void setCertificateVerifier(BaseCertificateVerifier* verifier);

protected:
	virtual void onConnect() override;

private:
	SslContextType _implTemplate;
	SslType _impl;
	std::vector<Certificate> _certChain;
};
