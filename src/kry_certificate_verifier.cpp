#include "kry_certificate_verifier.h"

CertificateReport KryCertficateVerifier::onVerify(bool preverification, Certificate* cert, const VerificationError& error)
{
	CertificateReport result(*cert);

	if (cert->isRevoked())
	{
		result.addIssue(Rank::Dangerous, "Revoked");
	}

	if ((containsCaseInsensitive(cert->getPublicKeyAlgorithm(), "RSA") && cert->getKeyBits() < 1024)
		|| (cert->getPublicKeyAlgorithm() == "id-ecPublicKey" && cert->getKeyBits() < 256))
	{
		result.addIssue(Rank::Dangerous, "Weak key size");
	}

	if (cert->getX509() == _serverCert)
	{
		if (!cert->getAlterantiveNames().empty())
		{
			for (const auto& name : cert->getAlterantiveNames())
			{
				auto res = checkSubjectName(name);
				if (res.first > Rank::Secure)
					result.addIssue(res.first, res.second);
			}
		}
		else
		{
			auto res = checkSubjectName(cert->getSubjectEntry("CN"));
			if (res.first > Rank::Secure)
				result.addIssue(res.first, res.second);
		}
	}

	if (containsCaseInsensitive(cert->getSignatureAlgorithm(), "SHA1"))
	{
		result.addIssue(Rank::AlmostSecure, "Use of SHA1");
	}

	if (cert->getCrlDistributionPoint().empty() && cert->getOcspResponder().empty())
	{
		result.addIssue(Rank::Dangerous, "No revocation address available");
	}

	if (!preverification)
	{
		if (error.result == VerificationResult::CertificateExpired)
		{
			result.addIssue(Rank::Dangerous, "Expired");
		}

		if (error.result == VerificationResult::IssuerCertificateMissing)
		{
			result.addIssue(Rank::Dangerous, "Issuer certificate unavailable");
		}

		if (error.result == VerificationResult::SelfSignedInChain || error.result == VerificationResult::TopmostIsSelfSigned)
		{
			result.addIssue(Rank::Dangerous, "Self-signed");
		}

		if (error.result == VerificationResult::InvalidCA)
		{
			result.addIssue(Rank::PossiblyDangerous, "Non-CA certificate used as CA");
		}

		if (error.result == VerificationResult::SubtreeViolation)
		{
			result.addIssue(Rank::PossiblyDangerous, "Violation of name constraint");
		}

		if (error.result == VerificationResult::InvalidPurpose)
		{
			result.addIssue(Rank::PossiblyDangerous, "Violation of key usage");
		}
	}

	return result;
}

std::pair<Rank, std::string> KryCertficateVerifier::checkSubjectName(const std::string& name) const
{
	auto serverName =_serverReport.getServerName();
	auto domains = split(serverName, ".");
	domains[0] = "*";
	auto wildcardName = join(domains.begin(), domains.end(), ".");

	if (name == serverName)
		return { Rank::Secure, "" };
	else if (name == wildcardName)
		return { Rank::AlmostSecure, "Subject name is wildcarded" };
	else
		return { Rank::Dangerous, "Subject name mismatch" };
}
