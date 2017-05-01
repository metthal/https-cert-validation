#pragma once

#include <string>

class Certificate;

class OcspClient
{
public:
	bool isRevoked(const Certificate& cert, const Certificate& issuer) const;
};
