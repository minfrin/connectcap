
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = connectcap
connectcap_SOURCES = connectcap.c

EXTRA_DIST = connectcap.spec
dist_man_MANS = connectcap.1

connectcap.1: connectcap
	which txt2man && ./connectcap --help | txt2man -s 1 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > connectcap.1 || true

