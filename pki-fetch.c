/*
 * PKI Fetch helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include <openssl/x509.h>

#include "pki-fetch.h"

int pki_crl_cb (const void *data, size_t len, void *cookie)
{
	const unsigned char *p = data;
	X509_CRL **ret = cookie, *c;

	if ((c = d2i_X509_CRL (NULL, &p, len)) != NULL) {
		*ret = c;
		return 1;
	}

	return 0;
}

int pki_fetch (const char *uri, int limit, pki_data_cb cb, void *cookie)
{
	if (strncmp (uri, "http", 4) == 0)
		return pki_http_fetch (uri, limit, cb, cookie);

	if (strncmp (uri, "ldap", 4) == 0)
		return pki_ldap_fetch (uri, limit, cb, cookie);

	return 0;
}
