#pragma once

#include <algorithm>
#include <functional>
#include <unordered_map>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "certificate.h"
#include "error.h"
#include "fn_ptr.h"
#include "http_client.h"
#include "ocsp_client.h"
#include "report.h"
#include "ssl_socket.h"
#include "socket.h"
#include "verification_error.h"

class BaseCertificateVerifier
{
public:
	using VerifyFnPtr = decltype(X509_STORE::verify_cb);
	using CrlVerifyFnPtr = decltype(X509_STORE::verify_cb);

	virtual ~BaseCertificateVerifier() = default;

	static int verificationCallback(BaseCertificateVerifier* verifier, int preverifyOk, X509_STORE_CTX* certStore)
	{
		VerificationError verificationError(X509_STORE_CTX_get_error(certStore));

		// Determine the depth of the current certificate
		std::size_t chainSize = sk_X509_num(certStore->chain);
		std::size_t depth;
		for (depth = 0; depth < chainSize; ++depth)
		{
			auto x509 = sk_X509_value(certStore->chain, depth);
			if (x509 == certStore->current_cert)
				break;
		}

		auto cert = verifier->getCertificate(certStore->current_cert);
		verifier->_serverReport.addCertificateReport(verifier->onVerify(preverifyOk == 1, cert, verificationError, depth));
		return 1;
	}

	static int crlVerificationCallback(BaseCertificateVerifier* verifier, int /*preverifyOk*/, X509_STORE_CTX* certStore)
	{
		VerificationError verificationError(X509_STORE_CTX_get_error(certStore));

		auto cert = verifier->getCertificate(certStore->current_cert);
		if (!cert->isRevoked())
			cert->setRevoked(verificationError.result == VerificationResult::Revoked);
		return 1;
	}

	ServerReport verify(const SslSocket* sslSocket)
	{
		_serverReport.setServerName(sslSocket->getUri().getHostname());
		_serverReport.setTlsVersion(sslSocket->getUsedTlsVersion());
		_serverReport.setCipher(sslSocket->getUsedCipher());

		if (_serverReport.getTlsVersion() == "TLSv1.1")
			_serverReport.addIssue(Rank::AlmostSecure, "TLSv1.1 used");
		else if (_serverReport.getTlsVersion() != "TLSv1.2")
			_serverReport.addIssue(Rank::Dangerous, "TLSv1.0 or older used");

		auto trustedStoreX509 = sslSocket->getTrustedStoreX509();

		// Try to download available CRLs
		bool checkCrl = false;
		STACK_OF(X509)* chain = sslSocket->getCertificateChainX509();
		_chainSize = sk_X509_num(chain);
		for (std::size_t i = 0; i < _chainSize; ++i)
		{
			auto cert = getCertificate(sk_X509_value(chain, i));

			// Prefer OCSP over CRL
			if (i + 1 != _chainSize && !cert->getOcspResponder().empty())
			{
				auto issuer = getCertificate(sk_X509_value(chain, i + 1));

				OcspClient ocsp;
				if (!cert->isRevoked())
					cert->setRevoked(ocsp.isRevoked(cert, issuer));
			}
			else if (!cert->getCrlDistributionPoint().empty())
			{
				Uri uri(cert->getCrlDistributionPoint());
				HttpClient crlDownloader(uri);
				auto crlPem = crlDownloader.request(uri.getResource());

				// Try PEM as first and if it fails try DER
				X509_CRL* crl = nullptr;
				auto bio = makeUnique(BIO_new_mem_buf(const_cast<char*>(crlPem.data()), crlPem.length() + 1), &BIO_free);
				if ((crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) == nullptr)
				{
					bio = makeUnique(BIO_new_mem_buf(const_cast<char*>(crlPem.data()), crlPem.length() + 1), &BIO_free);
					crl = d2i_X509_CRL_bio(bio.get(), nullptr);
					if (!crl)
						continue;
				}

				checkCrl = true;
				X509_STORE_add_crl(trustedStoreX509, crl);
				X509_CRL_free(crl);
			}
		}

		if (checkCrl)
		{
			// We need to create completely new X509_STORE_CTX here
			auto crlCertStore = makeUnique(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
			X509_STORE_CTX_init(crlCertStore.get(), trustedStoreX509, sslSocket->getServerCertificateX509(), sslSocket->getCertificateChainX509());
			X509_STORE_CTX_set_default(crlCertStore.get(), "ssl_client");
			X509_STORE_CTX_set_verify_cb(crlCertStore.get(), getCrlVerifyCallbackPtr());
			X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(crlCertStore.get()), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
			X509_verify_cert(crlCertStore.get());
		}

		auto certStore = makeUnique(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
		X509_STORE_CTX_init(certStore.get(), trustedStoreX509, sslSocket->getServerCertificateX509(), sslSocket->getCertificateChainX509());
		X509_STORE_CTX_set_default(certStore.get(), "ssl_client");
		X509_STORE_CTX_set_verify_cb(certStore.get(), getVerifyCallbackPtr());
		X509_verify_cert(certStore.get());

		return _serverReport;
	}

protected:
	virtual CertificateReport onVerify(bool preverification, Certificate* cert, const VerificationError& error, std::size_t chainDepth) = 0;

	virtual VerifyFnPtr getVerifyCallbackPtr() = 0;
	virtual VerifyFnPtr getCrlVerifyCallbackPtr() = 0;

	ServerReport _serverReport;
	std::size_t _chainSize;
	std::unordered_map<X509*, Certificate> _certTable;

private:
	Certificate* getCertificate(X509* x509)
	{
		// Mapping of X509 certificates to Certificate instances
		auto itr = _certTable.find(x509);
		if (itr == _certTable.end())
			std::tie(itr, std::ignore) = _certTable.emplace(x509, Certificate{x509});;

		return &itr->second;
	}
};

template <typename Tag>
class CertificateVerifier : public BaseCertificateVerifier
{
public:
	VerifyFnPtr getVerifyCallbackPtr() override final
	{
		using namespace std::placeholders;

		std::function<int(int, X509_STORE_CTX*)> callback = std::bind(&verificationCallback, this, _1, _2);
		return makeFnPtr<0, Tag>(callback).pointer();
	}

	CrlVerifyFnPtr getCrlVerifyCallbackPtr() override final
	{
		using namespace std::placeholders;

		std::function<int(int, X509_STORE_CTX*)> callback = std::bind(&crlVerificationCallback, this, _1, _2);
		return makeFnPtr<1, Tag>(callback).pointer();
	}
};
