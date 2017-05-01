#include <iomanip>
#include <iostream>

#include "certificate_verifier.h"
#include "http_client.h"
#include "kry_certificate_verifier.h"
#include "ocsp_client.h"
#include "ssl_socket.h"
#include "ssl_suite.h"

int main()
{
	SslSuite ssl;

	auto certVerifier = std::make_unique<KryCertficateVerifier>();

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

			certVerifier->verify(&sock);

			std::cout << "\tTLS: " << sock.getUsedTlsVersion() << std::endl;
			std::cout << "\tCipher: " << sock.getUsedCipher() << std::endl;
		}
		catch (const SslHandshakeError& error)
		{
			std::cerr << "FAIL: " << error.what() << std::endl;
		}
	}
}
