/*
 * PKI CRL Helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <glob.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

X509_CRL *pki_read_crl (const char *path)
{
	FILE *f;
	X509_CRL *crl;

	if ((f = fopen (path, "rb")) == NULL)
		return NULL;

	crl = PEM_read_X509_CRL (f, NULL, NULL, NULL);

	fclose (f);
	return crl;
}

int pki_write_crl (const X509_CRL *crl, const char *path)
{
	int len;
	char *tmp;
	FILE *f;
	int ok;

	len = snprintf (NULL, 0, "%s-new", path) + 1;

	if ((tmp = malloc (len)) == NULL)
		return 0;

	snprintf (tmp, len, "%s-new", path);

	if ((f = fopen (tmp, "wb")) == NULL)
		ok = 0;
	else {
		ok  = PEM_write_X509_CRL (f, (void *) crl);
		ok &= fclose (f) == 0;
	}

	if (ok)
		ok &= rename (tmp, path) == 0;

	free (tmp);
	return ok;
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

X509_CRL *pki_load_crl (const X509 *cert, const char *root, char **path)
{
	EVP_PKEY *pkey;
	unsigned long hash;
	int len;
	char *pattern;
	glob_t g;
	size_t i;
	X509_CRL *ret = NULL, *crl;

	if ((pkey = X509_get0_pubkey (cert)) == NULL)
		return NULL;

	if (root == NULL)
		root = "/etc/ssl/certs";

	hash = X509_NAME_hash (X509_get_subject_name (cert));

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

		ret = crl;
		goto found;
	}

	if (path != NULL)
		*path = pki_crl_path (root, hash);
found:
	globfree (&g);
no_glob:
	free (pattern);
no_pattern:
	EVP_PKEY_free (pkey);
	return ret;
}

static ASN1_INTEGER *pki_crl_number (const X509_CRL *o)
{
	return X509_CRL_get_ext_d2i (o, NID_crl_number, NULL, NULL);
}

int pki_save_crl (const X509 *cert, const char *root, const X509_CRL *crl)
{
	X509_CRL *cur;
	char *path = NULL;
	ASN1_INTEGER *cur_n, *new_n;
	int ok = 1, update = 0;

	if ((cur = pki_load_crl (cert, root, &path)) != NULL) {
		cur_n = pki_crl_number (cur);
		new_n = pki_crl_number (crl);

		if (cur_n == NULL || new_n == NULL)
			ok = 0;
		else
			update = ASN1_INTEGER_cmp (cur_n, new_n) < 0;

		ASN1_INTEGER_free (new_n);
		ASN1_INTEGER_free (cur_n);
		X509_CRL_free (cur);
	}
	else {
		if (path == NULL)
			ok = 0;
		else
			update = 1;
	}

	if (update)
		ok &= pki_write_crl (crl, path);

	free (path);
	return ok;
}
