#pragma once

class SslSuite
{
public:
	SslSuite();
	~SslSuite();

	SslSuite(const SslSuite&) = delete;
	SslSuite(SslSuite&&) = delete;
};
