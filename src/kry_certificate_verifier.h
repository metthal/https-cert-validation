#pragma once

#include "certificate_verifier.h"

class KryCertficateVerifier : public CertificateVerifier<KryCertficateVerifier>
{
protected:
	virtual CertificateReport onVerify(bool preverification, Certificate* cert, const VerificationError& error) override;

	std::pair<Rank, std::string> checkSubjectName(const std::string& name) const;
};
