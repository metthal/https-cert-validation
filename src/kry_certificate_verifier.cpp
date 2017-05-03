#include "kry_certificate_verifier.h"

CertificateReport KryCertficateVerifier::onVerify(bool preverification, Certificate* cert, const VerificationError& error)
{
	CertificateReport result(*cert);

	if (cert->isRevoked())
	{
		result.addIssue(Rank::Dangerous, "revocation_status", "Revoked");
	}

	if ((containsCaseInsensitive(cert->getPublicKeyAlgorithm(), "RSA") && cert->getKeyBits() < 1024)
		|| (cert->getPublicKeyAlgorithm() == "id-ecPublicKey" && cert->getKeyBits() < 256))
	{
		result.addIssue(Rank::Dangerous, "key_size", "Weak key size");
	}

	if (cert->getX509() == _serverCert)
	{
		if (!cert->getAlterantiveNames().empty())
		{
			for (const auto& name : cert->getAlterantiveNames())
			{
				auto res = checkSubjectName(name);
				if (res.first > Rank::Secure)
					result.addIssue(res.first, "alternative_names", res.second);
			}
		}
		else
		{
			auto res = checkSubjectName(cert->getSubjectEntry("CN"));
			if (res.first > Rank::Secure)
				result.addIssue(res.first, "subject_name", res.second);
		}
	}

	if (containsCaseInsensitive(cert->getSignatureAlgorithm(), "SHA1"))
	{
		result.addIssue(Rank::AlmostSecure, "signature_algorithm", "Use of SHA1");
	}

	if (!preverification)
	{
		if (error.result == VerificationResult::CertificateExpired)
		{
			result.addIssue(Rank::Dangerous, "expiration", "Expired");
		}

		if (error.result == VerificationResult::IssuerCertificateMissing)
		{
			result.addIssue(Rank::Dangerous, "issuer", "Issuer certificate unavailable");
		}

		if (error.result == VerificationResult::SelfSignedInChain || error.result == VerificationResult::TopmostIsSelfSigned)
		{
			result.addIssue(Rank::Dangerous, "issuer", "Self-signed");
		}

		if (error.result == VerificationResult::InvalidCA)
		{
			result.addIssue(Rank::Dangerous, "ca", "Non-CA certificate used as CA");
		}

		if (error.result == VerificationResult::SubtreeViolation)
		{
			result.addIssue(Rank::Dangerous, "name_constraint", "Violation of name constraint");
		}

		if (error.result == VerificationResult::InvalidPurpose)
		{
			result.addIssue(Rank::Dangerous, "key_usage", "Violation of key usage");
		}
	}

	return result;
}

std::pair<Rank, std::string> KryCertficateVerifier::checkSubjectName(const std::string& name) const
{
	if (name == _serverReport.getServerName())
		return { Rank::Secure, "" };
	else if (name == "*.minotaur.fi.muni.cz")
		return { Rank::AlmostSecure, "CN for *.minotaur.fi.muni.cz" };
	else if (isSuffix(_serverReport.getServerName(), name))
		return { Rank::PossiblyDangerous, "CN for another subdomain at minotaur.fi.muni.cz" };
	else
		return { Rank::Dangerous, "CN mismatch" };
}
