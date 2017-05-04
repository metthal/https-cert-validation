#include <iomanip>
#include <iostream>

#include "certificate_verifier.h"
#include "kry_certificate_verifier.h"
#include "ssl_socket.h"
#include "ssl_suite.h"

int main()
{
	SslSuite ssl;

	Report report;
	for (std::size_t i = 0; i < 100; ++i)
	{
		std::ostringstream urlWriter;
		urlWriter << std::setw(2) << std::setfill('0') << i << ".minotaur.fi.muni.cz";
		auto url = urlWriter.str();

		try
		{
			SslSocket sock(url, 443);
			//sock.useDefaultTrustStore();
			sock.useTrustStore("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
			sock.useTrustStore("crocs-ca.pem");
			sock.enableCrlVerification();
			sock.connect();

			//Certificate cert(sock.getServerCertificateX509());
			//cert.saveToFile("certs/" + url + ".pem");

			KryCertficateVerifier certVerifier;
			report.addServerReport(certVerifier.verify(&sock));
		}
		catch (const SslHandshakeError& error)
		{
			std::cerr << "FAIL: " << error.what() << std::endl;
		}
	}

	auto reports = report.getServerReports();
	for (auto itr = reports.begin(), end = reports.end(); itr != end; ++itr)
	{
		const auto& report = *itr;
		std::cout << report.getServerName() << ", " << report.getRank() << ", ";

		auto issues = report.getIssuesString("/");
		if (issues.empty())
			std::cout << "OK";
		else
			std::cout << issues;

		if (itr + 1 != end)
			std::cout << std::endl;
	}
}
