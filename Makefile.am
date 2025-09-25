
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = connectdump
connectdump_SOURCES = connectdump.c

EXTRA_DIST = connectdump.spec
dist_man_MANS = connectdump.1

connectdump.1: connectdump
	which txt2man && ./connectdump --help | txt2man -s 1 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > connectdump.1 || true

