/*
 * PKI CA Scan helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <glob.h>

#include <openssl/x509v3.h>

#include "pki.h"

int pki_scan_cas (const char *root, pki_ca_cb cb, void *cookie)
{
	int len, stop = 0;
	char *pattern;
	glob_t g;
	size_t i;
	X509 *c;

	if (root == NULL)
		root = "/etc/ssl/certs";

	len = snprintf (NULL, 0, "%s/*.pem", root) + 1;

	if ((pattern = malloc (len)) == NULL)
		return 0;

	snprintf (pattern, len, "%s/*.pem", root);

	g.gl_offs = 0;

	if (glob (pattern, GLOB_NOSORT, NULL, &g) != 0)
		goto no_glob;

	for (i = 0; !stop && i < g.gl_pathc; ++i) {
		if ((c = pki_read_crt (g.gl_pathv[i])) == NULL)
			continue;

		if (X509_check_ca (c) != 0)
			stop = cb (c, cookie);

		X509_free (c);
	}

	globfree (&g);
	free (pattern);
	return 1;
no_glob:
	free (pattern);
	return 0;
}
