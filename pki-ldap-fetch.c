/*
 * LDAP Fetch helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define LDAP_DEPRECATED  1
#include <ldap.h>

#include "pki-fetch.h"

static int scan_attrs (LDAP *ldap, LDAPMessage *e, pki_data_cb cb, void *cookie)
{
	char *name;
	BerElement *be;
	int stop = 0;
	struct berval **vals;
	size_t i;

	if ((name = ldap_first_attribute (ldap, e, &be)) == NULL)
		return 0;

	vals = ldap_get_values_len (ldap, e, name);

	for (i = 0; !stop && vals[i] != NULL; ++i)
		stop = cb (vals[i]->bv_val, vals[i]->bv_len, cookie);

	ldap_value_free_len (vals);
	ber_memfree (name);

	ber_free (be, 0);
	return stop;
}

int pki_ldap_fetch (const char *uri, int limit, pki_data_cb cb, void *cookie)
{
	const int version = LDAP_VERSION3;
	LDAPURLDesc *desc;
	LDAP *ldap;
	LDAPMessage *m, *e;
	int ok = 0;

	if (ldap_url_parse (uri, &desc) != 0)
		return 0;

	/*
	 * URI must point to single attribute
	 */
	if (desc->lud_scope != LDAP_SCOPE_BASE || desc->lud_attrs == NULL ||
	    desc->lud_attrs[0] == NULL || desc->lud_attrs[1] != NULL)
		goto no_attr;

	if ((ldap = ldap_init (desc->lud_host, desc->lud_port)) == NULL)
		goto no_ldap;

	ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &version);

	ok = ldap_search_ext_s (ldap, desc->lud_dn, desc->lud_scope,
				desc->lud_filter, desc->lud_attrs, 0,
				NULL, NULL, NULL, limit, &m) == 0;
	if (!ok)
		goto no_search;

	if ((e = ldap_first_entry (ldap, m)) != NULL)
		ok = scan_attrs (ldap, e, cb, cookie);

	ldap_msgfree (m);
no_search:
	ldap_destroy (ldap);
no_ldap:
no_attr:
	ldap_free_urldesc (desc);
	return ok;
}
