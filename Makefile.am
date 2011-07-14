ACLOCAL_AMFLAGS = -I m4

SUBDIRS = arpcgen libarpc arpcbind arpcinfo test

# Set the order for the subdirs
libarpc: arpcgen
arpcbind: arpcgen libarpc
arpcinfo: arpcgen libarpc
test: arpcgen libarpc
