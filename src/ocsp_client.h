#pragma once

#include <string>

#include "error.h"

class Certificate;

class OcspResponseError : public Error
{
public:
	OcspResponseError() noexcept : Error("Failed to retrieve OCSP response.") {}
};

class OcspClient
{
public:
	bool isRevoked(const Certificate* cert, const Certificate* issuer) const;
};
