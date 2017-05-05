#pragma once

#include <openssl/x509.h>

#include "error.h"

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
