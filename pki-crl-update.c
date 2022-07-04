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

int pki_scan_dps (const X509 *ca, pki_dp_cb cb, void *cookie)
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
