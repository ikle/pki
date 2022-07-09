/*
 * PKI Fetch helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PKI_FETCH_H
#define PKI_FETCH_H  1

#include <stddef.h>

typedef int pki_data_cb (const void *data, size_t len, void *cookie);

int pki_ldap_fetch (const char *uri, int limit, pki_data_cb cb, void *cookie);

int pki_fetch (const char *uri, int limit, pki_data_cb cb, void *cookie);

#endif  /* PKI_FETCH_H */
