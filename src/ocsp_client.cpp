#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "certificate.h"
#include "ocsp_client.h"
#include "scope_exit.h"
#include "utils.h"

/**
 * This method is insipred by `apps/ocsp.c`. A lot of code is just copied from it.
 */
bool OcspClient::isRevoked(const Certificate& cert, const Certificate& issuer) const
{
	char* host = nullptr;
	char* port = nullptr;
	char* resource = nullptr;
	int needsSsl = 0;

	ON_SCOPE_EXIT(freeResources,
			CRYPTO_free(host);
			CRYPTO_free(port);
			CRYPTO_free(resource);
		);

	// Parse hostname, port, resource and whether we need SSL/TLS or not
	if (OCSP_parse_url(cert.getOcspResponder().c_str(), &host, &port, &resource, &needsSsl) != 1)
		throw;

	// Code inspired by `apps/ocsp.c` in OpenSSL library
	auto ocspBio = BIO_new_connect(host);

	ON_SCOPE_EXIT(freeOcspBio,
			BIO_free_all(ocspBio);
		);

	BIO_set_conn_port(ocspBio, port);
	if (needsSsl == 1)
	{
		auto sslCtx = makeUnique(SSL_CTX_new(SSLv23_method()), &SSL_CTX_free);
		SSL_CTX_set_mode(sslCtx.get(), SSL_MODE_AUTO_RETRY);

		auto sslBio = BIO_new_ssl(sslCtx.get(), 1);
		ocspBio = BIO_push(sslBio, ocspBio);
	}

	if (BIO_do_connect(ocspBio) != 1)
		throw;

	// Obtain X509 structures out of our own internal certificate representation
	auto subjectX509 = makeUnique(cert.getX509(), &X509_free);
	auto issuerX509 = makeUnique(issuer.getX509(), &X509_free);

	// Create OCSP request and add our certificates to it
	auto ocspRequest = makeUnique(OCSP_REQUEST_new(), &OCSP_REQUEST_free);
	auto id = OCSP_cert_to_id(EVP_sha1(), subjectX509.get(), issuerX509.get());
	OCSP_request_add0_id(ocspRequest.get(), id);

	// Create OCSP request context and add to it `Host` HTTP header
	// There is no way to do it through OCSP request so we need to do it through context
	// We need to associate OCSP request with the context after we set the `Host` HTTP header beacuse then this header
	// is written to the packet after the body was written and that means malformed HTTP request
	auto ocspRequestCtx = makeUnique(OCSP_sendreq_new(ocspBio, resource, nullptr, -1), &OCSP_REQ_CTX_free);
	OCSP_REQ_CTX_add1_header(ocspRequestCtx.get(), "Host", host);
	OCSP_REQ_CTX_set1_req(ocspRequestCtx.get(), ocspRequest.get());

	// Send OCSP request
	OCSP_RESPONSE* ocspResponse = nullptr;
	OCSP_sendreq_nbio(&ocspResponse, ocspRequestCtx.get());
	ON_SCOPE_EXIT(freeOcspResponse,
			OCSP_RESPONSE_free(ocspResponse);
		);

	// Obtain OCSP response data
	auto status = OCSP_response_status(ocspResponse);
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
		throw;

	auto ocspResponseStatus = makeUnique(OCSP_response_get1_basic(ocspResponse), &OCSP_BASICRESP_free);
	auto responseData = ocspResponseStatus->tbsResponseData;

	// Try to find whether the certificate is revoked in the OCSP response
	std::size_t responsesCount = sk_OCSP_SINGLERESP_num(responseData->responses);
	for (std::size_t i = 0; i < responsesCount; ++i)
	{
		auto response = sk_OCSP_SINGLERESP_value(responseData->responses, i);
		if (response->certStatus->type == V_OCSP_CERTSTATUS_REVOKED)
			return true;
	}

	return false;
}
