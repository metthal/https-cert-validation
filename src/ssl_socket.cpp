#include <openssl/err.h>

#include "ssl_socket.h"

SslSocket::SslSocket(const Uri& uri, std::uint16_t port) : Socket(uri, port),
	_implTemplate(SSL_CTX_new(SSLv23_method()), &SSL_CTX_free),
	_impl(nullptr),
	_connectionTry(0)
{
}

std::string SslSocket::getUsedTlsVersion() const
{
	return SSL_get_version(_impl);
}

std::string SslSocket::getUsedCipher() const
{
	return SSL_get_cipher(_impl);
}

X509* SslSocket::getServerCertificateX509() const
{
	auto chain = getCertificateChainX509();
	return sk_X509_value(chain, 0);
}

STACK_OF(X509)* SslSocket::getCertificateChainX509() const
{
	return SSL_get_peer_cert_chain(_impl);
}

X509_STORE* SslSocket::getTrustedStoreX509() const
{
	return SSL_CTX_get_cert_store(_implTemplate.get());
}

void SslSocket::useDefaultTrustStore()
{
	SSL_CTX_set_default_verify_paths(_implTemplate.get());
}

void SslSocket::useTrustStore(const std::string& store)
{
	SSL_CTX_load_verify_locations(_implTemplate.get(), store.c_str(), nullptr);
}

void SslSocket::onConnect()
{
	auto sslBio = BIO_new_ssl(_implTemplate.get(), 1);
	_bio = BIO_push(sslBio, _bio);

	BIO_get_ssl(_bio, &_impl);
	SSL_set_tlsext_host_name(_impl, _uri.getHostname().c_str()); // SNI

	switch (_connectionTry)
	{
		// On the first try, try TLSv1.2
		case 0:
			break;
		// On the second try, fallback to TLSv1.1
		case 1:
			SSL_set_options(_impl, SSL_OP_NO_TLSv1_2);
			break;
		// On the third try, fallback to TLSv1.0
		case 2:
			SSL_set_options(_impl, SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1);
			break;
		// On the fourth try just end abnormally
		default:
			throw SslHandshakeError();
	}

	try
	{
		if (BIO_do_handshake(_bio) <= 0)
			throw SslHandshakeError();

		if (!makeUnique(SSL_get_peer_certificate(_impl), &X509_free))
			throw SslHandshakeError();
	}
	catch (const SslHandshakeError&)
	{
		_connectionTry++;
		reconnect();
	}
}
