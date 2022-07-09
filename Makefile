DESCRIPTION = Public Key Infrastructure helpers
URL = https://github.com/ikle/pki

LIBNAME	= ikle-pki
LIBVER	= 0
LIBREV	= 0.1

DEPENDS = openssl

LDFLAGS += -llber -lldap

include make-core.mk
