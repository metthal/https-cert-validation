#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/x509.h>

class Certificate
{
public:
	Certificate();
	Certificate(X509* impl);
	Certificate(const Certificate&) = default;
	Certificate(Certificate&&) = default;

	Certificate& operator=(const Certificate&) = default;
	Certificate& operator=(Certificate&&) = default;

	const std::string& getSubjectName() const;
	const std::string& getIssuerName() const;
	std::string getSubjectEntry(const std::string& key) const;
	std::string getIssuerEntry(const std::string& key) const;
	const std::string& getSerialNumber() const;
	const std::string& getCrlDistributionPoint() const;
	const std::string& getOcspResponder() const;
	const std::string& getPublicKeyAlgorithm() const;
	std::size_t getKeyBits() const;
	const std::string& getSignatureAlgorithm() const;
	const std::vector<std::string>& getAlterantiveNames() const;
	const std::string& getPEM() const;

	X509* getX509() const;

	void saveToFile(const std::string& filePath) const;

	bool operator==(const Certificate& cert) const;
	bool operator!=(const Certificate& cert) const;

private:
	using CryptoStringType = std::unique_ptr<char, decltype(&CRYPTO_free)>;

	void load(X509* impl);
	std::map<std::string, std::string> loadNameEntries(X509_NAME* name);

	std::string _subjectName;
	std::string _issuerName;
	std::map<std::string, std::string> _subjectEntries;
	std::map<std::string, std::string> _issuerEntries;
	std::string _serialNumber;
	std::string _crlDistributionPoint;
	std::string _ocspResponder;
	std::string _publicKeyAlgorithm;
	std::size_t _keyBits;
	std::string _signatureAlgorithm;
	std::vector<std::string> _alternativeNames;
	std::string _pem;
};
