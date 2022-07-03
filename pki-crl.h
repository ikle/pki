/*
 * PKI CRL Helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PKI_CRL_H
#define PKI_CRL_H  1

#include <openssl/x509.h>

X509_CRL *pki_read_crl (const char *path);
int pki_write_crl (const X509_CRL *crl, const char *path);

X509_CRL *pki_load_crl (const X509 *cert, const char *root, char **path);
int pki_save_crl (const X509 *cert, const char *root, const X509_CRL *crl);

#endif  /* PKI_CRL_H */
