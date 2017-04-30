#include <iostream>

#include <openssl/err.h>

#include "ssl_socket.h"

template <SslMethod Method>
SslSocket<Method>::SslSocket(const std::string& hostname, std::uint16_t port) : Socket(hostname, port),
	_implTemplate(SSL_CTX_new(SslMethodTraits<Method>::initFn()), &SSL_CTX_free),
	_impl(nullptr, &SSL_free),
	_certChain()
{
}

template <SslMethod Method>
const Certificate& SslSocket<Method>::getPeerCertificate() const
{
	return _certChain.front();
}

template <SslMethod Method>
const std::vector<Certificate>& SslSocket<Method>::getPeerCertificateChain() const
{
	return _certChain;
}

template <SslMethod Method>
void SslSocket<Method>::useDefaultTrustStore()
{
	SSL_CTX_set_default_verify_paths(_implTemplate.get());
}

template <SslMethod Method>
void SslSocket<Method>::useTrustStore(const std::string& store)
{
	SSL_CTX_load_verify_locations(_implTemplate.get(), store.c_str(), nullptr);
}

template <SslMethod Method>
void SslSocket<Method>::enableCrlVerification()
{
	auto verifyCrlParam = makeUnique(X509_VERIFY_PARAM_new(), &X509_VERIFY_PARAM_free);
	X509_VERIFY_PARAM_set_flags(verifyCrlParam.get(), X509_V_FLAG_CRL_CHECK);
	SSL_CTX_set1_param(_implTemplate.get(), verifyCrlParam.get());
}

template <SslMethod Method>
void SslSocket<Method>::setCertificateVerifier(BaseCertificateVerifier* verifier)
{
	SSL_CTX_set_verify(_implTemplate.get(), SSL_VERIFY_PEER, verifier->getVerifyCallbackPtr());
	_implTemplate->cert_store->lookup_crls = verifier->getCrlLookupCallbackPtr();
}

template <SslMethod Method>
void SslSocket<Method>::onConnect()
{
	_impl.reset(SSL_new(_implTemplate.get()));
	SSL_set_tlsext_host_name(_impl.get(), _hostname.c_str());
	SSL_set_fd(_impl.get(), _socket.native_handle());

	auto err = SSL_connect(_impl.get());
	if (err <= 0)
	{
		std::cerr << SSL_get_error(_impl.get(), err) << std::endl;
		int sslError;
		while ((sslError = ERR_get_error()) != 0)
			std::cerr << ERR_error_string(sslError, nullptr) << std::endl;
		throw SslHandshakeError();
	}

	auto x509Peer = makeUnique(SSL_get_peer_certificate(_impl.get()), &X509_free);
	if (!x509Peer)
		throw SslHandshakeError();

	auto x509Chain = SSL_get_peer_cert_chain(_impl.get());
	if (x509Chain)
	{
		std::size_t certsCount = sk_X509_num(x509Chain);
		for (std::size_t i = 0; i < certsCount; ++i)
		{
			auto x509 = sk_X509_value(x509Chain, i);
			_certChain.emplace_back(x509);
		}
	}

	std::cout << "\tSSL version: " << SSL_get_version(_impl.get()) << std::endl;
	std::cout << "\tSSL cipher: " << SSL_get_cipher(_impl.get()) << std::endl;
}

template class SslSocket<SslMethod::SSLv23_TLSv1x>;
