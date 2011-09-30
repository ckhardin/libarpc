ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/libarpc
LDADD = ../libarpc/libarpc.la -latf-c -lssl
CLEANFILES =
EXTRA_DIST =

tests_PROGRAMS = t_libarpc
tests_DATA = Atffile

t_libarpc_SOURCES = t_libarpc.c test_xdr.c test_rpc.c test_rpc.h

## Generated
EXTRA_DIST += testobjs_xdr.x testobjs_rpc.x
nodist_t_libarpc_SOURCES = testobjs_xdr.h testobjs_rpc.h
nodist_t_libarpc_SOURCES += testobjs_xdr.c testobjs_rpc.c
test_xdr.$(OBJEXT): testobjs_xdr.h 
test_rpc.$(OBJEXT): testobjs_rpc.h

testobjs_xdr.h: $(top_srcdir)/test/testobjs_xdr.x
	$(top_builddir)/arpcgen/arpcgen -h -o $@ $<
testobjs_xdr.c: $(top_srcdir)/test/testobjs_xdr.x
	$(top_builddir)/arpcgen/arpcgen -c -o $@ $<

testobjs_rpc.h: $(top_srcdir)/test/testobjs_rpc.x
	$(top_builddir)/arpcgen/arpcgen -h -o $@ $<
testobjs_rpc.c: $(top_srcdir)/test/testobjs_rpc.x
	$(top_builddir)/arpcgen/arpcgen -c -o $@.xdr $<
	$(top_builddir)/arpcgen/arpcgen -l -o $@.clnt $<
	$(top_builddir)/arpcgen/arpcgen -m -o $@.srv $<
	cat $@.xdr $@.clnt $@.srv > $@
	rm $@.xdr $@.clnt $@.srv

CLEANFILES += testobjs_xdr.h testobjs_rpc.h
CLEANFILES += testobjs_xdr.c testobjs_rpc.c

#
# Derived from ATF autoconf
#

TEST_ENVIRONMENT = PATH=$(prefix)/bin:$${PATH} \
		   PKG_CONFIG_PATH=$(prefix)/lib/pkgconfig

testsdir = $(exec_prefix)/tests
pkgtestsdir = $(testsdir)/$(PACKAGE)

installcheck-local: installcheck-atf
.PHONY: installcheck-atf
installcheck-atf:
	logfile=$$(pwd)/installcheck.log; \
	fifofile=$$(pwd)/installcheck.fifo; \
	cd $(pkgtestsdir); \
	rm -f $${fifofile}; \
	mkfifo $${fifofile}; \
	cat $${fifofile} | tee $${logfile} | \
		$(TESTS_ENVIRONMENT) $(ATFREPORT) & \
		$(TESTS_ENVIRONMENT) $(ATFRUN) >>$${fifofile}; \
	res=$${?}; \
	wait; \
	rm $${fifofile}; \
	echo; \
	echo "The verbatim output of atf-run has been saved to" \
	     "installcheck.log; exit was $${res}"; \
	test $${res} -eq 0
CLEANFILES += installcheck.fifo installcheck.log

pkgtests_DATA = Atffile
EXTRA_DIST += $(pkgtests_DATA)

