/*
 * PKI DPs test
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "pki.h"

static int dp_cb (const X509 *ca, const char *uri, void *cookie)
{
	char *name = X509_NAME_oneline (X509_get_subject_name (ca), NULL, 0);

	if (name == NULL)
		return 0;

	printf ("%s:\n\t%s\n", name, uri);

	OPENSSL_free (name);
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
