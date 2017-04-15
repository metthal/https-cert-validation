#include "certificate.h"

Certificate::Certificate(X509* impl) : _subjectEntries(), _issuerEntries()
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
