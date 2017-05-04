#include <unordered_set>

#include "report.h"
#include "utils.h"

void CertificateReport::setRank(Rank rank)
{
	_rank = rank > _rank ? rank : _rank;
}

Rank CertificateReport::getRank() const
{
	return _rank;
}

const Certificate& CertificateReport::getCertificate() const
{
	return _cert;
}

const std::vector<std::string>& CertificateReport::getIssues() const
{
	return _issues;
}

std::string CertificateReport::getIssuesString(const std::string& delim) const
{
	return join(_issues.begin(), _issues.end(), delim);
}

void ServerReport::setRank(Rank rank)
{
	_rank = rank > _rank ? rank : _rank;
}

const std::string& ServerReport::getServerName() const
{
	return _serverName;
}

const std::string& ServerReport::getTlsVersion() const
{
	return _tlsVersion;
}

const std::string& ServerReport::getCipher() const
{
	return _cipher;
}

Rank ServerReport::getRank() const
{
	auto certRank = std::max_element(_reports.begin(), _reports.end(),
			[](const auto& lhs, const auto& rhs) {
				return lhs.getRank() < rhs.getRank();
			})->getRank();

	return certRank > _rank ? certRank : _rank;
}

const std::vector<CertificateReport>& ServerReport::getCertificateReports() const
{
	return _reports;
}

std::string ServerReport::getIssuesString(const std::string& delim) const
{
	std::vector<std::string> result;

	for (const auto& issue : _issues)
		insertOrderedUnique(result, issue);

	for (const auto& report : _reports)
	{
		for (const auto& issue : report.getIssues())
			insertOrderedUnique(result, issue);
	}

	return join(result.begin(), result.end(), delim);
}

const std::vector<ServerReport>& Report::getServerReports() const
{
	return _reports;
}
