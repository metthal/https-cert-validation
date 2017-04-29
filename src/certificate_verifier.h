#pragma once

#include <functional>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certificate.h"
#include "error.h"
#include "fn_ptr.h"
#include "http_client.h"
#include "socket.h"
#include "uri_parser.h"

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
	using CrlLookupFnPtr = decltype(X509_STORE::lookup_crls);

	virtual ~BaseCertificateVerifier() = default;

	static int verificationCallback(BaseCertificateVerifier* verifier, int preverifyOk, X509_STORE_CTX* certStore)
	{
		Certificate cert(certStore->current_cert);
		VerificationError verificationError(X509_STORE_CTX_get_error(certStore));
		certStore->error = X509_V_OK;

		if (verificationError.result == VerificationResult::UnavailableCRL && cert.getCrlDistributionPoint().empty())
		{
			certStore->error = X509_V_OK;
			return 1;
		}

		return verifier->verify(preverifyOk == 1, cert, verificationError) ? 1 : 0;
	}

	static STACK_OF(X509_CRL)* crlLookupCallback(BaseCertificateVerifier* verifier, X509_STORE_CTX* certStore, X509_NAME* name)
	{
		Certificate cert(certStore->current_cert);

		STACK_OF(X509_CRL)* result = nullptr;
		if (!cert.getCrlDistributionPoint().empty())
		{
			result = sk_X509_CRL_new_null();

			UriParser uriPraser(cert.getCrlDistributionPoint());
			HttpClient<Socket> crlDownloader(uriPraser.getHostname(), 80);
			crlDownloader.connect();
			auto crlPem = crlDownloader.request(uriPraser.getResource());

			X509_CRL* crl = nullptr;
			auto bio = makeUnique(BIO_new_mem_buf(crlPem.data(), crlPem.length() + 1), &BIO_free);
			if ((crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) == nullptr)
			{
				bio = makeUnique(BIO_new_mem_buf(crlPem.data(), crlPem.length() + 1), &BIO_free);
				crl = d2i_X509_CRL_bio(bio.get(), nullptr);
			}

			if (crl != nullptr)
				sk_X509_CRL_push(result, crl);
		}

		return result;
	}

	virtual VerifyFnPtr getVerifyCallbackPtr() = 0;
	virtual CrlLookupFnPtr getCrlLookupCallbackPtr() = 0;

protected:
	virtual bool verify(bool preverification, const Certificate& cert, const VerificationError& error) = 0;

private:
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

	CrlLookupFnPtr getCrlLookupCallbackPtr() override final
	{
		using namespace std::placeholders;

		std::function<STACK_OF(X509_CRL)*(X509_STORE_CTX*, X509_NAME*)> callback = std::bind(&crlLookupCallback, this, _1, _2);
		return makeFnPtr<1, Tag>(callback).pointer();
	}
};
