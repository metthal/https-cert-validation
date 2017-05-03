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

const std::unordered_map<std::string, std::vector<std::string>>& CertificateReport::getIssues() const
{
	return _issues;
}

std::string CertificateReport::getIssuesString(const std::string& delim) const
{
	std::unordered_set<std::string> allIssues;
	for (const auto& issues : mapGetValues(_issues))
		for (const auto& issue : issues)
			allIssues.insert(issue);

	std::vector<std::string> result(allIssues.begin(), allIssues.end());
	std::sort(result.begin(), result.end());
	return join(result.begin(), result.end(), delim);
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
	std::unordered_set<std::string> allIssues;
	for (const auto& attrIssue : _issues)
		for (const auto& issue : attrIssue.second)
			allIssues.insert(issue);

	for (const auto& report : _reports)
	{
		const auto& issues = report.getIssues();
		for (const auto& attrIssue : issues)
			for (const auto& issue : attrIssue.second)
				allIssues.insert(issue);
	}

	std::vector<std::string> result(allIssues.begin(), allIssues.end());
	std::sort(result.begin(), result.end());
	return join(result.begin(), result.end(), delim);
}

const std::vector<ServerReport>& Report::getServerReports() const
{
	return _reports;
}
