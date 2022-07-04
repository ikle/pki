/*
 * PKI Certificate Load helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <openssl/pem.h>

#include "pki.h"

X509 *pki_read_crt (const char *path)
{
	FILE *f;
	X509 *crt;

	if ((f = fopen (path, "rb")) == NULL)
		return NULL;

	crt = PEM_read_X509 (f, NULL, NULL, NULL);

	fclose (f);
	return crt;
}
