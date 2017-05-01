#include <iomanip>
#include <iostream>

#include "certificate_verifier.h"
#include "http_client.h"
#include "ocsp_client.h"
#include "ssl_socket.h"
#include "ssl_suite.h"

class MyCertVerifier : public CertificateVerifier<MyCertVerifier>
{
protected:
	virtual bool onVerify(bool preverification, const Certificate& cert, const VerificationError& error) override
	{
		std::cout << "\tVerification started" << std::endl;
		std::cout << "\t\tPreverification: " << std::boolalpha << preverification << std::endl;
		std::cout << "\t\tSubject: " << cert.getSubjectName() << std::endl;
		std::cout << "\t\tSubject CN: " << cert.getSubjectEntry("CN") << std::endl;
		std::cout << "\t\tIssuer: " << cert.getIssuerName() << std::endl;
		std::cout << "\t\tSerial number: " << cert.getSerialNumber() << std::endl;
		std::cout << "\t\tCRL Distribution Point: " << cert.getCrlDistributionPoint() << std::endl;
		std::cout << "\t\tError: " << error.message << std::endl;
		return true;
	}
};

int main()
{
	SslSuite ssl;

	auto certVerifier = std::make_unique<MyCertVerifier>();

	for (std::size_t i = 0; i < 100; ++i)
	{
		std::ostringstream urlWriter;
		urlWriter << std::setw(2) << std::setfill('0') << i << ".minotaur.fi.muni.cz";
		auto url = urlWriter.str();

		std::cout << url << std::endl;

		try
		{
			SslSocket sock(url, 443);
			//sock.useDefaultTrustStore();
			sock.useTrustStore("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
			sock.useTrustStore("crocs-ca.pem");
			sock.enableCrlVerification();
			sock.connect();

			sock.getServerCertificate().saveToFile("certs/" + url + ".pem");

			const auto& chain = sock.getCertificateChain();
			for (auto itr = chain.begin(), end = chain.end(); itr != end; ++itr)
			{
				if (itr + 1 == end)
					break;

				const auto& cert = *itr;
				const auto& issuer = *(itr + 1);
				if (!cert.getOcspResponder().empty())
				{
					OcspClient ocsp;
					std::cout << "OCSP: " << cert.getSubjectName() << " " << std::boolalpha << ocsp.isRevoked(cert, issuer) << std::endl;
				}
			}

			certVerifier->verify(&sock);
		}
		catch (const SslHandshakeError& error)
		{
			std::cerr << "FAIL: " << error.what() << std::endl;
		}
	}
}
