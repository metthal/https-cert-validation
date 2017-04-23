#pragma once

#include <map>
#include <memory>
#include <string>

#include <openssl/crypto.h>
#include <openssl/x509.h>

class Certificate
{
public:
	Certificate();
	Certificate(X509* impl);

	const std::string& getSubjectName() const;
	const std::string& getIssuerName() const;
	std::string getSubjectEntry(const std::string& key);
	std::string getIssuerEntry(const std::string& key);
	const std::string& getSerialNumber() const;

	void saveToFile(const std::string& filePath) const;

private:
	using CryptoStringType = std::unique_ptr<char, decltype(&CRYPTO_free)>;

	void load(X509* impl);
	std::map<std::string, std::string> loadNameEntries(X509_NAME* name);

	std::string _subjectName;
	std::string _issuerName;
	std::map<std::string, std::string> _subjectEntries;
	std::map<std::string, std::string> _issuerEntries;
	std::string _serialNumber;
	std::string _pem;
};
