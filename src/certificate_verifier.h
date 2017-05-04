#pragma once

#include <algorithm>
#include <functional>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

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

class UnknownVerificationResultError : public Error
{
public:
	UnknownVerificationResultError(int result) noexcept : Error("Unknown verification result '" + std::to_string(result) + "' found.") {}
};

enum class VerificationResult
{
	Ok,
	CertificateExpired,
	Revoked,
	UnavailableCRL,
	IssuerCertificateMissing,
	UnableToVerifyServerCertificate,
	TopmostIsSelfSigned,
	InvalidPurpose,
	InvalidCA,
	SelfSignedInChain,
	SubtreeViolation,
	Unknown
};

struct VerificationError
{
	VerificationError(int x509error)
	{
		switch (x509error)
		{
			case X509_V_OK:
				result = VerificationResult::Ok;
				break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
				result = VerificationResult::CertificateExpired;
				break;
			case X509_V_ERR_CERT_REVOKED:
				result = VerificationResult::Revoked;
				break;
			case X509_V_ERR_UNABLE_TO_GET_CRL:
				result = VerificationResult::UnavailableCRL;
				break;
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				result = VerificationResult::IssuerCertificateMissing;
				break;
			case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				result = VerificationResult::UnableToVerifyServerCertificate;
				break;
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
				result = VerificationResult::TopmostIsSelfSigned;
				break;
			case X509_V_ERR_INVALID_PURPOSE:
				result = VerificationResult::InvalidPurpose;
				break;
			case X509_V_ERR_INVALID_CA:
				result = VerificationResult::InvalidCA;
				break;
			case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
				result = VerificationResult::SelfSignedInChain;
				break;
			case X509_V_ERR_PERMITTED_VIOLATION:
				result = VerificationResult::SubtreeViolation;
				break;
			default:
				throw UnknownVerificationResultError(x509error);
		}

		message = X509_verify_cert_error_string(x509error);
	}

	VerificationResult result;
	std::string message;
};

class BaseCertificateVerifier
{
public:
	using VerifyFnPtr = decltype(X509_STORE::verify_cb);
	using CrlVerifyFnPtr = decltype(X509_STORE::verify_cb);

	virtual ~BaseCertificateVerifier() = default;

	static int verificationCallback(BaseCertificateVerifier* verifier, int preverifyOk, X509_STORE_CTX* certStore)
	{
		VerificationError verificationError(X509_STORE_CTX_get_error(certStore));

		auto cert = verifier->getCertificate(certStore->current_cert);
		if (!verifier->_chain.empty())
		{
			auto itr = std::find_if(verifier->_chain.begin(), verifier->_chain.end(),
					[&cert](auto itrCert) {
						return itrCert->getSubjectName() == cert->getIssuerName();
					});
			if (itr != verifier->_chain.end())
				verifier->_chain.insert(itr + 1, cert);
		}
		else
			verifier->_chain.push_back(cert);

		verifier->_serverReport.addCertificateReport(verifier->onVerify(preverifyOk == 1, cert, verificationError));
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
		_serverCert = sslSocket->getServerCertificateX509();

		if (_serverReport.getTlsVersion() == "TLSv1.1")
			_serverReport.addIssue(Rank::AlmostSecure, "TLSv1.1 used");
		else if (_serverReport.getTlsVersion() != "TLSv1.2")
			_serverReport.addIssue(Rank::Dangerous, "TLSv1.0 or older used");

		auto trustedStoreX509 = sslSocket->getTrustedStoreX509();

		// Try to download available CRLs
		bool checkCrl = false;
		STACK_OF(X509)* chain = sslSocket->getCertificateChainX509();
		std::size_t chainSize = sk_X509_num(chain);
		for (std::size_t i = 0; i < chainSize; ++i)
		{
			auto cert = getCertificate(sk_X509_value(chain, i));

			if (i + 1 != chainSize && !cert->getOcspResponder().empty())
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
			X509_STORE_CTX_set_verify_cb(crlCertStore.get(), getCrlVerifyCallbackPtr());
			X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(crlCertStore.get()), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
			X509_verify_cert(crlCertStore.get());
		}

		auto certStore = makeUnique(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
		X509_STORE_CTX_init(certStore.get(), trustedStoreX509, sslSocket->getServerCertificateX509(), sslSocket->getCertificateChainX509());
		X509_STORE_CTX_set_verify_cb(certStore.get(), getVerifyCallbackPtr());
		X509_verify_cert(certStore.get());

		return _serverReport;
	}

protected:
	virtual CertificateReport onVerify(bool preverification, Certificate* cert, const VerificationError& error) = 0;

	virtual VerifyFnPtr getVerifyCallbackPtr() = 0;
	virtual VerifyFnPtr getCrlVerifyCallbackPtr() = 0;

	ServerReport _serverReport;
	X509* _serverCert;
	std::unordered_map<X509*, Certificate> _certTable;
	std::vector<Certificate*> _chain;

private:
	Certificate* getCertificate(X509* x509)
	{
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
