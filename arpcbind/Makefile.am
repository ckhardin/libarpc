
AM_CPPFLAGS = -I$(top_srcdir)/libarpc/include
AM_CFLAGS = -DPORTMAP -DINET6 -DLIBWRAP
LDADD = -lwrap -lutil ../../lib/libarpc.la -lcrypt -lssl

BUILT_SOURCES = rpcb_prot.h pmap_prot.h
CLEANFILES = $(BUILT_SOURCES)

bin_PROGRAMS = arpcbind
arpcbind_SOURCES = check_bound.c rpcb_stat.c rpcb_svc_4.c rpcbind.c \
	pmap_svc.c rpcb_svc.c rpcb_svc_com.c security.c warmstart.c \
	util.c rpcb_prot.h pmap_prot.h

rpcb_prot.h: $(top_srcdir)/libarpc/include/rpcb_prot.x
	$(top_srcdir)/arpcgen/arpcgen -h -o rpcb_prot.h \
		$(top_srcdir)/libarpc/include/rpcb_prot.x

pmap_prot.h: $(top_srcdir)/libarpc/include/pmap_prot.x
	$(top_srcdir)/arpcgen/arpcgen -h -o pmap_prot.h \
		$(top_srcdir)/libarpc/include/pmap_prot.x

dist_man_MANS = arpcbind.8
