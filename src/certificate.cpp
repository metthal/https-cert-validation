#include <fstream>
#include <vector>

#include <openssl/pem.h>

#include "certificate.h"
#include "utils.h"

Certificate::Certificate() :  _subjectName(), _issuerName(), _subjectEntries(), _issuerEntries(), _serialNumber()
{
}

Certificate::Certificate(X509* impl) : Certificate()
{
	load(impl);
}

const std::string& Certificate::getSubjectName() const
{
	return _subjectName;
}

const std::string& Certificate::getIssuerName() const
{
	return _issuerName;
}

std::string Certificate::getSubjectEntry(const std::string& key)
{
	auto itr = _subjectEntries.find(key);
	return itr != _subjectEntries.end() ? itr->second : std::string{};
}

std::string Certificate::getIssuerEntry(const std::string& key)
{
	auto itr = _issuerEntries.find(key);
	return itr != _issuerEntries.end() ? itr->second : std::string{};
}

const std::string& Certificate::getSerialNumber() const
{
	return _serialNumber;
}

void Certificate::load(X509* impl)
{
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

	_pem.clear();
	int bytesRead;
	std::vector<char> pemReader(1024);
	while ((bytesRead = BIO_gets(pemWriter.get(), pemReader.data(), pemReader.size())) > 0)
	{
		_pem += std::string{pemReader.begin(), pemReader.begin() + bytesRead};
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
