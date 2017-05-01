#include <openssl/ocsp.h>

#include "certificate.h"
#include "ocsp_client.h"
#include "scope_exit.h"
#include "socket.h"
#include "ssl_socket.h"
#include "uri.h"

/**
 * This method is insipred by `apps/ocsp.c`. A lot of code is just copied from it.
 */
bool OcspClient::isRevoked(const Certificate& cert, const Certificate& issuer) const
{
	Uri uri(cert.getOcspResponder());

	std::unique_ptr<Socket> socket;
	if (uri.getProtocol() == "https")
		socket = std::make_unique<SslSocket>(uri);
	else
		socket = std::make_unique<Socket>(uri);

	socket->connect();

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
	auto ocspRequestCtx = makeUnique(OCSP_sendreq_new(socket->getBIO(), uri.getResource().c_str(), nullptr, -1), &OCSP_REQ_CTX_free);
	OCSP_REQ_CTX_add1_header(ocspRequestCtx.get(), "Host", uri.getHostname().c_str());
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
		throw OcspResponseError();

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
