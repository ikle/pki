/*
 * PKI CRL Save helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "pki-crl.h"

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

static ASN1_INTEGER *pki_crl_number (const X509_CRL *o)
{
	return X509_CRL_get_ext_d2i (o, NID_crl_number, NULL, NULL);
}

int pki_save_crl (const X509 *cert, const char *root, const X509_CRL *crl)
{
	ASN1_INTEGER *new_n, *cur_n;
	X509_CRL *cur;
	char *path = NULL;
	int ok = 1, update = 0;

	if ((new_n = pki_crl_number (crl)) == NULL)
		return 0;

	if ((cur = pki_load_crl (cert, root, &path)) != NULL) {
		if ((cur_n = pki_crl_number (cur)) == NULL)
			ok = 0;
		else {
			update = ASN1_INTEGER_cmp (cur_n, new_n) < 0;
			ASN1_INTEGER_free (cur_n);
		}

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
	ASN1_INTEGER_free (new_n);
	return ok;
}
