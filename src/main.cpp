#include <iomanip>
#include <iostream>

#include "certificate_verifier.h"
#include "ssl_socket.h"
#include "ssl_suite.h"

class MyCertVerifier : public CertificateVerifier<MyCertVerifier>
{
protected:
	virtual bool verify(bool preverification, const Certificate& cert, const VerificationError& error) override
	{
		std::cout << "\tVerification started" << std::endl;
		std::cout << "\t\tPreverification: " << std::boolalpha << preverification << std::endl;
		std::cout << "\t\tSubject: " << cert.getSubjectName() << std::endl;
		std::cout << "\t\tIssuer: " << cert.getIssuerName() << std::endl;
		std::cout << "\t\tError: " << error.message << std::endl;
		return true;
	}
};

int main()
{
	SslSuite ssl;

	auto certVerifier = std::make_unique<MyCertVerifier>();

	//for (std::size_t i = 0; i < 100; ++i)
	for (std::size_t i = 18; i < 19; ++i)
	//for (std::size_t i = 0; i < 1; ++i)
	{
		std::ostringstream urlWriter;
		urlWriter << std::setw(2) << std::setfill('0') << i << ".minotaur.fi.muni.cz";
		auto url = urlWriter.str();

		std::cout << url << std::endl;

		try
		{
			SslSocket<SslMethod::SSLv23_TLSv1x> sock(url, 443);
			sock.useTrustStore("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
			sock.useTrustStore("/home/marek/school/KRY/https/crocs-ca.pem");
			sock.setCertificateVerifier(certVerifier.get());
			sock.connect();
		}
		catch (const SslHandshakeError& error)
		{
			std::cerr << "FAIL: " << error.what() << std::endl;
		}
	}
}
