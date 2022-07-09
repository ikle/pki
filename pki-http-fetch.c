/*
 * HTTP Fetch helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "pki-fetch.h"

struct data {
	char *data;
	size_t len;
};

static size_t data_cb (void *content, size_t size, size_t nmemb, void *cookie)
{
	struct data *o = cookie;
	size_t len = size * nmemb;
	char *p;

	if ((p = realloc (o->data, o->len + len)) == NULL)
		return 0;

	o->data = p;
	memcpy (p + o->len, content, len);

	o->len += len;
	return len;
}

int pki_http_fetch (const char *uri, int limit, pki_data_cb cb, void *cookie)
{
	CURL *c;
	struct data o = { NULL, 0 };
	int ok = 0;

	if ((c = curl_easy_init ()) == NULL)
		return 0;

	if (curl_easy_setopt (c, CURLOPT_URL, uri) != 0 ||
	    curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, data_cb) != 0 ||
	    curl_easy_setopt (c, CURLOPT_WRITEDATA, &o) != 0)
		goto no_opt;

	curl_easy_setopt (c, CURLOPT_TIMEOUT, 1);
	curl_easy_setopt (c, CURLOPT_FOLLOWLOCATION, 1);

	if (curl_easy_perform (c) == 0)
		ok = cb (o.data, o.len, cookie);

	free (o.data);
no_opt:
	curl_easy_cleanup (c);
	return ok;
}
