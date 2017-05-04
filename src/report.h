#pragma once

#include <unordered_set>

#include <boost/container/flat_map.hpp>
#include <boost/optional.hpp>

#include "certificate.h"

enum Rank
{
	Secure = 1,
	AlmostSecure = 2,
	PossiblyDangerous = 3,
	Dangerous = 4
};

class CertificateReport
{
public:
	template <typename CertT>
	CertificateReport(CertT&& cert) : _rank(Rank::Secure), _cert(std::forward<CertT>(cert)), _issues()
	{
	}

	void setRank(Rank rank);

	template <typename IssueT>
	void addIssue(Rank rank, IssueT&& issue)
	{
		setRank(rank);
		insertOrderedUnique(_issues, std::forward<IssueT>(issue));
	}

	Rank getRank() const;
	const Certificate& getCertificate() const;
	const std::vector<std::string>& getIssues() const;
	std::string getIssuesString(const std::string& delim) const;

private:
	Rank _rank;
	Certificate _cert;
	std::vector<std::string> _issues;
};

class ServerReport
{
public:
	ServerReport() : _rank(Rank::Secure), _serverName(), _tlsVersion(), _cipher(), _reports(), _issues()
	{
	}

	void setRank(Rank rank);

	template <typename NameT>
	void setServerName(NameT&& name)
	{
		_serverName = std::forward<NameT>(name);
	}

	template <typename NameT>
	void setTlsVersion(NameT&& version)
	{
		_tlsVersion = std::forward<NameT>(version);
	}

	template <typename NameT>
	void setCipher(NameT&& cipherSuite)
	{
		_cipher = std::forward<NameT>(cipherSuite);
	}

	template <typename ReportT>
	void addCertificateReport(ReportT&& report)
	{
		_reports.push_back(std::forward<ReportT>(report));
	}

	template <typename IssueT>
	void addIssue(Rank rank, IssueT&& issue)
	{
		setRank(rank);
		insertOrderedUnique(_issues, std::forward<IssueT>(issue));
	}

	const std::string& getServerName() const;
	const std::string& getTlsVersion() const;
	const std::string& getCipher() const;
	Rank getRank() const;
	const std::vector<CertificateReport>& getCertificateReports() const;
	std::string getIssuesString(const std::string& delim) const;

private:
	Rank _rank;
	std::string _serverName;
	std::string _tlsVersion;
	std::string _cipher;
	std::vector<CertificateReport> _reports;
	std::vector<std::string> _issues;
};

class Report
{
public:
	template <typename ReportT>
	void addServerReport(ReportT&& report)
	{
		_reports.push_back(std::forward<ReportT>(report));
	}

	const std::vector<ServerReport>& getServerReports() const;

private:
	std::vector<ServerReport> _reports;
};
