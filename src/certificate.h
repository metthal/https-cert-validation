#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/x509.h>

enum KeyUsage
{
	None = 0,
	EncipherOnly = 1,
	CrlSigning = 2,
	CertificateSigning = 4,
	KeyAgreement = 8,
	DataEncipherment = 16,
	KeyEncipherment = 32,
	NonRepudiation = 64,
	DigitalSignature = 128,
	DecipherOnly = 256
};

class Certificate
{
public:
	Certificate();
	Certificate(X509* impl);
	Certificate(const Certificate&) = default;
	Certificate(Certificate&&) = default;

	Certificate& operator=(const Certificate&) = default;
	Certificate& operator=(Certificate&&) = default;

	void setRevoked(bool set);

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
	bool isCA() const;
	std::size_t getMaxCAPathLength() const;
	KeyUsage getKeyUsage() const;
	std::string getKeyUsageString() const;
	const std::string& getPEM() const;
	bool isRevoked() const;
	X509* getX509() const;

	void saveToFile(const std::string& filePath) const;

	bool operator==(const Certificate& cert) const;
	bool operator!=(const Certificate& cert) const;

private:
	using CryptoStringType = std::unique_ptr<char, decltype(&CRYPTO_free)>;

	void load(X509* impl);
	std::map<std::string, std::string> loadNameEntries(X509_NAME* name);

	X509* _impl;
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
	bool _isCA;
	std::size_t _maxCAPathLength;
	std::uint32_t _keyUsage;
	std::string _pem;
	bool _revoked;
};
