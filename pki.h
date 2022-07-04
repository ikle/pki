/*
 * PKI helpers
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PKI_H
#define PKI_H  1

#include <openssl/x509.h>

X509 *pki_read_crt (const char *path);

typedef int pki_ca_cb (const X509 *ca, void *cookie);
int pki_scan_cas (const char *root, pki_ca_cb cb, void *cookie);

X509_CRL *pki_read_crl (const char *path);
int pki_write_crl (const X509_CRL *crl, const char *path);

X509_CRL *pki_load_crl (const X509 *ca, const char *root, char **path);
int pki_save_crl (const X509 *ca, const char *root, const X509_CRL *crl);

typedef int pki_dp_cb (const X509 *ca, const char *uri, void *cookie);
int pki_scan_dps (const X509 *ca, pki_dp_cb cb, void *cookie);

#endif  /* PKI_H */
