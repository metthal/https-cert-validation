#include <fstream>
#include <vector>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "certificate.h"
#include "utils.h"

Certificate::Certificate() : _impl(nullptr), _subjectName(), _issuerName(), _subjectEntries(), _issuerEntries(), _serialNumber(), _crlDistributionPoint(),
	_ocspResponder(), _publicKeyAlgorithm(), _keyBits(0), _signatureAlgorithm(), _alternativeNames(), _isCA(false), _maxCAPathLength(0),
	_keyUsage(0), _pem(), _revoked(false)
{
}

Certificate::Certificate(X509* impl) : Certificate()
{
	load(impl);
}

void Certificate::setRevoked(bool set)
{
	_revoked = set;
}

const std::string& Certificate::getSubjectName() const
{
	return _subjectName;
}

const std::string& Certificate::getIssuerName() const
{
	return _issuerName;
}

std::string Certificate::getSubjectEntry(const std::string& key) const
{
	auto itr = _subjectEntries.find(key);
	return itr != _subjectEntries.end() ? itr->second : std::string{};
}

std::string Certificate::getIssuerEntry(const std::string& key) const
{
	auto itr = _issuerEntries.find(key);
	return itr != _issuerEntries.end() ? itr->second : std::string{};
}

const std::string& Certificate::getSerialNumber() const
{
	return _serialNumber;
}

const std::string& Certificate::getCrlDistributionPoint() const
{
	return _crlDistributionPoint;
}

const std::string& Certificate::getOcspResponder() const
{
	return _ocspResponder;
}

const std::string& Certificate::getPublicKeyAlgorithm() const
{
	return _publicKeyAlgorithm;
}

std::size_t Certificate::getKeyBits() const
{
	return _keyBits;
}

const std::string& Certificate::getSignatureAlgorithm() const
{
	return _signatureAlgorithm;
}

const std::vector<std::string>& Certificate::getAlterantiveNames() const
{
	return _alternativeNames;
}

bool Certificate::isCA() const
{
	return _isCA;
}

std::size_t Certificate::getMaxCAPathLength() const
{
	return _maxCAPathLength;
}

KeyUsage Certificate::getKeyUsage() const
{
	return static_cast<KeyUsage>(_keyUsage);
}

std::string Certificate::getKeyUsageString() const
{
	std::vector<std::string> parts;
	if (_keyUsage & KeyUsage::DigitalSignature)
		parts.push_back("Digital Signature");

	if (_keyUsage & KeyUsage::NonRepudiation)
		parts.push_back("Non Repudiation");

	if (_keyUsage & KeyUsage::KeyEncipherment)
		parts.push_back("Key Encipherment");

	if (_keyUsage & KeyUsage::DataEncipherment)
		parts.push_back("Data Encipherment");

	if (_keyUsage & KeyUsage::KeyAgreement)
		parts.push_back("Key Agreement");

	if (_keyUsage & KeyUsage::CertificateSigning)
		parts.push_back("Certificate Signing");

	if (_keyUsage & KeyUsage::CrlSigning)
		parts.push_back("CRL Signing");

	if (_keyUsage & KeyUsage::EncipherOnly)
		parts.push_back("Encipher Only");

	if (_keyUsage & KeyUsage::DecipherOnly)
		parts.push_back("Decipher Only");

	return join(parts.begin(), parts.end(), ", ");
}

const std::string& Certificate::getPEM() const
{
	return _pem;
}

bool Certificate::isRevoked() const
{
	return _revoked;
}

X509* Certificate::getX509() const
{
	return _impl;
}

void Certificate::load(X509* impl)
{
	_impl = impl;

	if (auto subjectName = X509_get_subject_name(impl))
	{
		_subjectName = CryptoStringType(X509_NAME_oneline(subjectName, nullptr, 0), &CRYPTO_free).get();
		_subjectEntries = loadNameEntries(subjectName);
	}

	if (auto issuerName = X509_get_issuer_name(impl))
	{
		_issuerName = CryptoStringType(X509_NAME_oneline(issuerName, nullptr, 0), &CRYPTO_free).get();
		_issuerEntries = loadNameEntries(issuerName);
	}

	if (auto sn = X509_get_serialNumber(impl))
	{
		_serialNumber = bytesToHexString(sn->data, sn->length);
	}

	auto pemWriter = makeUnique(BIO_new(BIO_s_mem()), &BIO_free);
	PEM_write_bio_X509(pemWriter.get(), impl);
	int bytesRead;
	std::vector<char> pemReader(1024);
	while ((bytesRead = BIO_gets(pemWriter.get(), pemReader.data(), pemReader.size())) > 0)
	{
		_pem += std::string{pemReader.begin(), pemReader.begin() + bytesRead};
	}

	if (auto crlDistPoints = impl->crldp)
	{
		for (int i = 0; i < sk_DIST_POINT_num(crlDistPoints) && _crlDistributionPoint.empty(); ++i)
		{
			auto distPoint = sk_DIST_POINT_value(crlDistPoints, i);
			if (distPoint->distpoint->type != 0)
				continue;

			auto names = distPoint->distpoint->name.fullname;
			for (int j = 0; j < sk_GENERAL_NAME_num(names) && _crlDistributionPoint.empty(); ++j)
			{
				auto name = sk_GENERAL_NAME_value(names, j);
				if (name->type != GEN_URI)
					continue;

				_crlDistributionPoint = std::string(name->d.ia5->data, name->d.ia5->data + name->d.ia5->length);
			}
		}
	}

	auto ocspInfo = makeUnique(X509_get1_ocsp(impl),
			[](STACK_OF(OPENSSL_STRING)* stack) {
				// I don't know why but when using sk_OPENSSL_STRING_free, it leaks memory
				X509_email_free(stack);
			});
	if (ocspInfo)
	{
		std::size_t ocspCount = sk_OPENSSL_STRING_num(ocspInfo.get());
		if (ocspCount > 0)
			_ocspResponder = sk_OPENSSL_STRING_value(ocspInfo.get(), 0);
	}

	if (auto pubkey = X509_get_pubkey(impl))
	{
		_keyBits = EVP_PKEY_bits(pubkey);
		_publicKeyAlgorithm = OBJ_nid2ln(OBJ_obj2nid(impl->cert_info->key->algor->algorithm));
	}

	_signatureAlgorithm = OBJ_nid2ln(OBJ_obj2nid(impl->sig_alg->algorithm));

	// Inspired by `http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem`
	if (auto names = reinterpret_cast<STACK_OF(GENERAL_NAME)*>(X509_get_ext_d2i(impl, NID_subject_alt_name, nullptr, nullptr)))
	{
		std::size_t nameCount = sk_GENERAL_NAME_num(names);
		for (std::size_t i = 0; i < nameCount; ++i)
		{
			auto name = sk_GENERAL_NAME_value(names, i);
			if (name->type == GEN_URI || name->type == GEN_DNS || name->type == GEN_EMAIL)
			{
				auto nameBuffer = name->d.uniformResourceIdentifier;
				_alternativeNames.emplace_back(ASN1_STRING_data(nameBuffer), ASN1_STRING_data(nameBuffer) + ASN1_STRING_length(nameBuffer));
			}
		}
	}

	if (auto constraint = reinterpret_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(impl, NID_basic_constraints, nullptr, nullptr)))
	{
		_isCA = constraint->ca != 0;
		_maxCAPathLength = ASN1_INTEGER_get(constraint->pathlen);
	}

	if (auto keyUsage = reinterpret_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(impl, NID_key_usage, nullptr, nullptr)))
	{
		std::uint16_t flags = 0;
		if (keyUsage->length > 1)
			flags |= static_cast<std::uint16_t>(keyUsage->data[1]) << 8;
		if (keyUsage->length > 0)
			flags |= static_cast<std::uint16_t>(keyUsage->data[0]);

		if (flags & X509v3_KU_DIGITAL_SIGNATURE)
			_keyUsage |= KeyUsage::DigitalSignature;
		if (flags & X509v3_KU_NON_REPUDIATION)
			_keyUsage |= KeyUsage::NonRepudiation;
		if (flags & X509v3_KU_KEY_ENCIPHERMENT)
			_keyUsage |= KeyUsage::KeyEncipherment;
		if (flags & X509v3_KU_DATA_ENCIPHERMENT)
			_keyUsage |= KeyUsage::DataEncipherment;
		if (flags & X509v3_KU_KEY_AGREEMENT)
			_keyUsage |= KeyUsage::KeyAgreement;
		if (flags & X509v3_KU_KEY_CERT_SIGN)
			_keyUsage |= KeyUsage::CertificateSigning;
		if (flags & X509v3_KU_CRL_SIGN)
			_keyUsage |= KeyUsage::CrlSigning;
		if (flags & X509v3_KU_ENCIPHER_ONLY)
			_keyUsage |= KeyUsage::EncipherOnly;
		if (flags & X509v3_KU_DECIPHER_ONLY)
			_keyUsage |= KeyUsage::DecipherOnly;
	}
}

std::map<std::string, std::string> Certificate::loadNameEntries(X509_NAME* name)
{
	std::map<std::string, std::string> result;

	auto numEntries = sk_X509_NAME_ENTRY_num(name->entries);
	for (auto i = 0; i < numEntries; ++i)
	{
		auto entry = sk_X509_NAME_ENTRY_value(name->entries, i);
		std::string key = OBJ_nid2sn(OBJ_obj2nid(entry->object));
		std::string value = std::string(entry->value->data, entry->value->data + entry->value->length);

		result.emplace(std::move(key), std::move(value));
	}

	return result;
}

void Certificate::saveToFile(const std::string& filePath) const
{
	std::ofstream file(filePath, std::ios::out | std::ios::trunc);
	if (!file.is_open())
		return;

	file << _pem;
}

bool Certificate::operator==(const Certificate& cert) const
{
	return _subjectName == cert._subjectName && _issuerName == cert._issuerName && _serialNumber == cert._serialNumber;
}

bool Certificate::operator!=(const Certificate& cert) const
{
	return !(*this == cert);
}
