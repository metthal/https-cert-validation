#pragma once

#include <functional>

#include <openssl/x509.h>

#include "certificate.h"
#include "error.h"
#include "fn_ptr.h"

class UnknownVerificationResultError : public Error
{
public:
	UnknownVerificationResultError(int result) noexcept : Error("Unknown verification result '" + std::to_string(result) + "' found.") {}
};

enum class VerificationResult
{
	Ok,
	CertificateExpired,
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
			default:
				result = VerificationResult::Unknown;
				break;
			//default:
			//	throw UnknownVerificationResultError(x509error);
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

	virtual ~BaseCertificateVerifier() = default;

	static int verificationCallback(BaseCertificateVerifier* verifier, int preverifyOk, X509_STORE_CTX* certStore)
	{
		Certificate cert(certStore->current_cert);
		return verifier->verify(preverifyOk == 1, cert, VerificationError{X509_STORE_CTX_get_error(certStore)}) ? 1 : 0;
	}

	virtual VerifyFnPtr getCallbackPtr() = 0;

protected:
	virtual bool verify(bool preverification, const Certificate& cert, const VerificationError& error) = 0;
};

template <typename Tag>
class CertificateVerifier : public BaseCertificateVerifier
{
public:
	VerifyFnPtr getCallbackPtr() override final
	{
		using namespace std::placeholders;
		
		std::function<int(int, X509_STORE_CTX*)> callback = std::bind(&verificationCallback, this, _1, _2);
		return makeFnPtr<Tag>(callback).pointer();
	}
};
