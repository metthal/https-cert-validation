#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl_suite.h"

SslSuite::SslSuite()
{
	SSL_load_error_strings();
	SSL_library_init();
}

SslSuite::~SslSuite()
{
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	ERR_remove_thread_state(nullptr);
	ERR_free_strings();
}
