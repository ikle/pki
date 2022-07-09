/*
 * PKI DPs test
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "pki.h"
#include "pki-fetch.h"

static void show_crl (const X509_CRL *crl)
{
	X509_NAME *name = X509_CRL_get_issuer (crl);

	printf ("\tCRL issuer: ");
	X509_NAME_print_ex_fp (stdout, name, 0, XN_FLAG_RFC2253);
	printf ("\n");
}

static int dp_cb (const X509 *ca, const char *uri, void *cookie)
{
	X509_NAME *name = X509_get_subject_name (ca);
	X509_CRL *crl;

	if (name == NULL)
		return 0;

	X509_NAME_print_ex_fp (stdout, name, 0, XN_FLAG_RFC2253);
	printf (":\n\t%s\n", uri);

	if (!pki_fetch (uri, 0, pki_crl_cb, &crl))
		return 0;

	show_crl (crl);
	pki_save_crl (ca, "crls", crl);

	X509_CRL_free (crl);
	return 0;
}

static int ca_cb (const X509 *ca, void *cookie)
{
	pki_scan_dps (ca, dp_cb, NULL);
	return 0;
}

int main (int argc, char *argv[])
{
	pki_scan_cas (NULL, ca_cb, NULL);
	return 0;
}
