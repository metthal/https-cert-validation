#include "kry_certificate_verifier.h"

bool KryCertficateVerifier::onVerify(bool preverification, const Certificate& cert, const VerificationError& error)
{
	std::cout << "\tVerification callback started" << std::endl;
	std::cout << "\t\tPreverification: " << std::boolalpha << preverification << std::endl;
	std::cout << "\t\tSubject: " << cert.getSubjectName() << std::endl;
	std::cout << "\t\tSubject CN: " << cert.getSubjectEntry("CN") << std::endl;
	std::cout << "\t\tIssuer: " << cert.getIssuerName() << std::endl;
	std::cout << "\t\tPublic Key Algorithm: " << cert.getPublicKeyAlgorithm() << std::endl;
	std::cout << "\t\tKey Size In Bits: " << cert.getKeyBits() << std::endl;
	std::cout << "\t\tSignature Algorithm: " << cert.getSignatureAlgorithm() << std::endl;
	std::cout << "\t\tSerial number: " << cert.getSerialNumber() << std::endl;
	std::cout << "\t\tCRL Distribution Point: " << cert.getCrlDistributionPoint() << std::endl;
	std::cout << "\t\tOCSP Responder Address: " << cert.getOcspResponder() << std::endl;
	std::cout << "\t\tError: " << error.message << std::endl;
	return true;
}
