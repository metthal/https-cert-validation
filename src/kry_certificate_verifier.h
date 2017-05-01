#pragma once

#include "certificate_verifier.h"

class KryCertficateVerifier : public CertificateVerifier<KryCertficateVerifier>
{
protected:
	virtual bool onVerify(bool preverification, const Certificate& cert, const VerificationError& error) override;
};
