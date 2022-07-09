/*
 * PKI CRL Load helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <glob.h>
#include <unistd.h>

#include <openssl/pem.h>

#include "pki.h"

X509_CRL *pki_read_crl (const char *path)
{
	FILE *f;
	X509_CRL *crl;

	if ((f = fopen (path, "rb")) == NULL)
		return NULL;

	if ((crl = PEM_read_X509_CRL (f, NULL, NULL, NULL)) == NULL) {
		rewind (f);
		crl = d2i_X509_CRL_fp (f, NULL);
	}

	fclose (f);
	return crl;
}

static char *pki_crl_path (const char *root, unsigned long hash)
{
	const unsigned max_col = 100;
	int len;
	char *path;
	unsigned i;

	len = snprintf (NULL, 0, "%s/%08lx.r%u", root, hash, max_col) + 1;

	if ((path = malloc (len)) == NULL)
		return NULL;

	for (i = 0; i < max_col; ++i) {
		snprintf (path, len, "%s/%08lx.r%u", root, hash, i);

		if (access (path, F_OK) != 0)
			return path;
	}

	free (path);
	return NULL;
}

X509_CRL *pki_load_crl (const X509 *ca, const char *root, char **path)
{
	EVP_PKEY *pkey;
	unsigned long hash;
	int len;
	char *pattern;
	glob_t g;
	size_t i;
	X509_CRL *crl;

	if ((pkey = X509_get0_pubkey (ca)) == NULL)
		return NULL;

	if (root == NULL)
		root = "/etc/ssl/certs";

	hash = X509_NAME_hash (X509_get_subject_name (ca));

	len = snprintf (NULL, 0, "%s/%08lx.r*", root, hash) + 1;

	if ((pattern = malloc (len)) == NULL)
		goto no_pattern;

	snprintf (pattern, len, "%s/%08lx.r*", root, hash);

	g.gl_offs = 0;

	if (glob (pattern, GLOB_NOSORT, NULL, &g) != 0)
		goto no_glob;

	for (i = 0; i < g.gl_pathc; ++i) {
		if ((crl = pki_read_crl (g.gl_pathv[i])) == NULL)
			continue;

		if (!X509_CRL_verify (crl, pkey)) {
			X509_CRL_free (crl);
			continue;
		}

		if (path != NULL) {
			*path = g.gl_pathv[i];
			g.gl_pathv[i] = NULL;
		}

		goto found;
	}

	globfree (&g);
no_glob:
	free (pattern);
no_pattern:
	EVP_PKEY_free (pkey);

	if (path != NULL)
		*path = pki_crl_path (root, hash);

	return NULL;
found:
	globfree (&g);
	free (pattern);
	EVP_PKEY_free (pkey);
	return crl;
}
