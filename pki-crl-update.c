/*
 * PKI CRL Update helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <glob.h>

#include <openssl/x509v3.h>

#include "pki.h"

static int pki_scan_ca_dps (const X509 *ca, pki_dp_cb cb, void *cookie)
{
	STACK_OF (DIST_POINT) *dps;
	int i, dp_count, j, gn_count;
	DIST_POINT *dp;
	GENERAL_NAMES *fullname;
	GENERAL_NAME *gn;

	dps = X509_get_ext_d2i (ca, NID_crl_distribution_points, NULL, NULL);
	if (dps == NULL)
		return 1;

	for (i = 0, dp_count = sk_DIST_POINT_num (dps); i < dp_count; ++i) {
		dp = sk_DIST_POINT_value (dps, i);

		if (dp->distpoint == NULL || dp->distpoint->type != 0)
			continue;

		fullname = dp->distpoint->name.fullname;
		gn_count = sk_GENERAL_NAME_num (fullname);

		for (j = 0; j < gn_count; ++j) {
			gn = sk_GENERAL_NAME_value (fullname, j);

			if (gn->type == GEN_URI &&
			    cb (ca, (void *) gn->d.ia5->data, cookie))
				break;
		}
	}

	CRL_DIST_POINTS_free (dps);
	return 1;
}

int pki_scan_dps (const X509 *ca, const char *root, pki_dp_cb cb, void *cookie)
{
	int len;
	char *pattern;
	glob_t g;
	size_t i;
	X509 *c;

	if (ca != NULL)
		return pki_scan_ca_dps (ca, cb, cookie);

	if (root == NULL)
		root = "/etc/ssl/certs";

	len = snprintf (NULL, 0, "%s/*.pem", root) + 1;

	if ((pattern = malloc (len)) == NULL)
		return 0;

	snprintf (pattern, len, "%s/*.pem", root);

	g.gl_offs = 0;

	if (glob (pattern, GLOB_NOSORT, NULL, &g) != 0)
		goto no_glob;

	for (i = 0; i < g.gl_pathc; ++i) {
		if ((c = pki_read_crt (g.gl_pathv[i])) == NULL)
			continue;

		if (X509_check_ca (c) != 0)
			pki_scan_ca_dps (c, cb, cookie);

		X509_free (c);
	}

	globfree (&g);
	free (pattern);
	return 1;
no_glob:
	free (pattern);
	return 0;
}
