/*
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1989 by Sun Microsystems, Inc.
 */

#include "compat.h"

#include <sys/cdefs.h>
#include <stdio.h>
#include <errno.h>
#include <netconfig.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpc.h>
#include <unistd.h>

#include "rpc_com.h"

/*
 * The five library routines in this file provide application access to the
 * system network configuration database, /etc/netconfig.  In addition to the
 * netconfig database and the routines for accessing it, the environment
 * variable NETPATH and its corresponding routines in getnetpath.c may also be
 * used to specify the network transport to be used.
 */


/*
 * netconfig errors
 */

#define NC_NONETCONFIG	ENOENT
#define NC_NOMEM	ENOMEM
#define NC_NOTINIT	EINVAL	    /* setnetconfig was not called first */
#define NC_BADFILE	EBADF	    /* format for netconfig file is bad */
#define NC_NOTFOUND	ENOPROTOOPT /* specified netid was not found */
#define NC_INVALID	EINVAL

/*
 * semantics as strings (should be in netconfig.h)
 */
#define NC_TPI_CLTS_S	    "tpi_clts"
#define	NC_TPI_COTS_S	    "tpi_cots"
#define	NC_TPI_COTS_ORD_S   "tpi_cots_ord"
#define	NC_TPI_RAW_S        "tpi_raw"

/*
 * flags as characters (also should be in netconfig.h)
 */
#define	NC_NOFLAG_C	'-'
#define	NC_VISIBLE_C	'v'
#define	NC_BROADCAST_C	'b'

/*
 * Character used to indicate there is no name-to-address lookup library
 */
#define NC_NOLOOKUP	"-"

static struct netconfig nc_defaults[] = {
	{"udp6", NC_TPI_CLTS, NC_VISIBLE, NC_INET6, NC_UDP, "/dev/udp6"},
	{"tcp6", NC_TPI_COTS_ORD, NC_VISIBLE, NC_INET6, NC_TCP, "/dev/tcp6"},
	{"udp", NC_TPI_CLTS, NC_VISIBLE, NC_INET, NC_UDP, "/dev/udp"},
	{"tcp", NC_TPI_COTS_ORD, NC_VISIBLE, NC_INET, NC_TCP, "/dev/tcp"},
	{"tls6", NC_TPI_COTS_ORD, NC_VISIBLE, NC_INET6, NC_TCP, "/dev/tcp6"},
	{"tls", NC_TPI_COTS_ORD, NC_VISIBLE, NC_INET, NC_TCP, "/dev/tcp"},
	{"rawip", NC_TPI_COTS_ORD, NC_NOFLAG, NC_INET, NC_NOPROTO, "-"},
	{"local", NC_TPI_COTS_ORD, NC_NOFLAG, NC_LOOPBACK, NC_NOPROTO, "-"},
	{NULL}
};

struct nc_handle {
	struct netconfig_handle_s   handler;
	int                         idx;
};

static void *__setnetconfig(void);

static nc_setnetconfig_fn_t nc_setnetconfig_fn = &__setnetconfig;

/*
 * When first called, getnetconfig() returns a pointer to the first entry in
 * the netconfig database, formatted as a struct netconfig.  On each subsequent
 * call, getnetconfig() returns a pointer to the next entry in the database.
 * getnetconfig() can thus be used to search the entire netconfig file.
 * getnetconfig() returns NULL at end of file.
 */
static struct netconfig *
__getnetconfig(void *handlep)
{
	struct nc_handle *handle;
	struct netconfig *nc;

	handle = (struct nc_handle *)handlep;
	if (!handle) {
		return NULL;
	}

	nc = &nc_defaults[handle->idx];
	if (!nc || !nc->nc_netid) {
		return NULL; /* eof */
	}

	handle->idx++;
	return nc;
}

/*
 * endnetconfig() may be called to "unbind" or "close" the netconfig database
 * when processing is complete, releasing resources for reuse.  endnetconfig()
 * may not be called before setnetconfig().  endnetconfig() returns 0 on
 * success and -1 on failure (for example, if setnetconfig() was not called
 * previously).
 */
static int
__endnetconfig(void *handlep)
{
	if (!handlep) {
		return -1;
	}

	free(handlep);
	return 0;
}

/*
 * A call to setnetconfig() establishes a /etc/netconfig "session".  A session
 * "handle" is returned on a successful call.  At the start of a session (after
 * a call to setnetconfig()) searches through the /etc/netconfig database will
 * proceed from the start of the file.  The session handle must be passed to
 * getnetconfig() to parse the file.  Each call to getnetconfig() using the
 * current handle will process one subsequent entry in /etc/netconfig.
 * setnetconfig() must be called before the first call to getnetconfig().
 * (Handles are used to allow for nested calls to setnetpath()).
 *
 * A new session is established with each call to setnetconfig(), with a new
 * handle being returned on each call.  Previously established sessions remain
 * active until endnetconfig() is called with that session's handle as an
 * argument.
 *
 * setnetconfig() need *not* be called before a call to getnetconfigent().
 * setnetconfig() returns a NULL pointer on failure (for example, if
 * the netconfig database is not present).
 */
static void *
__setnetconfig(void)
{
	struct nc_handle *handle;

	handle = malloc(sizeof(*handle));
	if (!handle) {
		return NULL;
	}
	memset(handle, 0, sizeof(handle));

	handle->handler.nh_getnetconfig = __getnetconfig;
	handle->handler.nh_endnetconfig = __endnetconfig;
	handle->handler.nh_handle = handle;
	handle->idx = 0;
	return &handle->handler;
}


void *
setnetconfig(void)
{
	if (nc_setnetconfig_fn) {
		return (*nc_setnetconfig_fn)();
	} else {
		return NULL;
	}
}

struct netconfig *
getnetconfig(void *handlep)
{
	struct netconfig_handle_s *handle;

	handle = (struct netconfig_handle_s *)handlep;
	if (!handle) {
		return NULL;
	} else {
		return (*handle->nh_getnetconfig)(handle->nh_handle);
	}
}

int
endnetconfig(void *handlep)
{
	struct netconfig_handle_s *handle;

	handle = (struct netconfig_handle_s *)handlep;
	if (!handle) {
		return -1;
	} else {
		return (*handle->nh_endnetconfig)(handle->nh_handle);
	}
}

void
setnetconfighandler(nc_setnetconfig_fn_t setfn)
{
	if (setfn) {
		nc_setnetconfig_fn = setfn;
	}
}



/*
 * getnetconfigent(netid) returns a pointer to the struct netconfig structure
 * corresponding to netid.  It returns NULL if netid is invalid (that is, does
 * not name an entry in the netconfig database).  It returns NULL and sets
 * errno in case of failure (for example, if the netconfig database cannot be
 * opened).
 */

int
getnetconfigentx(const char *netid, struct netconfig **ncpp)
{
	struct netconfig *ncp;
	void *handle;

	if (!netid || !ncpp) {
		return NC_INVALID;
	}
	
	handle = setnetconfig();
	if (!handle) {
		return NC_NOMEM;
	}

	while ((ncp = getnetconfig(handle)) != NULL) {
		if (strcmp(ncp->nc_netid, netid) == 0) {
			ncp = dupnetconfigent(ncp);
			endnetconfig(handle);
			*ncpp = ncp;
			if (ncp) {
				return 0;
			} else {
				return NC_NOMEM;
			}
		}
	}

	endnetconfig(handle);
	*ncpp = NULL;
	return NC_NOTFOUND;
}

struct netconfig *
getnetconfigent(const char *netid)
{
	struct netconfig *nc;
	int rc;

	rc = getnetconfigentx(netid, &nc);
	if (rc == 0) {
		return nc;
	} else {
		return NULL;
	}
}

/*
 * freenetconfigent(netconfigp) frees the netconfig structure pointed to by
 * netconfigp (previously returned by getnetconfigent()).
 */

void
freenetconfigent(struct netconfig *netconfigp)
{
    if (netconfigp != NULL) {
	    free(netconfigp);
    }
    return;
}

/*
 * Returns a string describing the reason for failure.
 */
const char *
nc_strerror(int err)
{
	const char *message;

	switch (err) {
	case NC_NONETCONFIG:
		message = "Netconfig database not found";
		break;
	case NC_NOMEM:
		message = "Not enough memory";
		break;
	case NC_NOTINIT:
		message = "Not initialized";
		break;
	case NC_BADFILE:
		message = "Netconfig database has invalid format";
		break;
	case NC_NOTFOUND:
		message = "Netid not found in netconfig database";
		break;
	default:
		message = "Unknown network selection error";
		break;
	}

	return message;
}

/*
 * Duplicates the matched netconfig buffer.
 */
struct netconfig *
dupnetconfigent(struct netconfig *ncp)
{
    struct netconfig	*p;
    char	*tmp;
    int		netidlen;
    int		protofmlylen;
    int		protolen;
    int		devlen;
    int		libscnt;
    int		libslen;
    int		len;
    u_int	i;

    if (!ncp) {
	    return NULL;
    }

    if (ncp->nc_netid) {
	    netidlen = strlen(ncp->nc_netid) + 1;
    } else {
	    netidlen = 1;
    }
    
    if (ncp->nc_protofmly) {
	    protofmlylen = strlen(ncp->nc_protofmly) + 1;
    } else {
	    protofmlylen = 1;
    }

    if (ncp->nc_proto) {
	    protolen = strlen(ncp->nc_proto) + 1;
    } else {
	    protolen = 1;
    }
    if (ncp->nc_device) {
	    devlen = strlen(ncp->nc_device) + 1;
    } else {
	    devlen = 1;
    }

    libscnt = ncp->nc_nlookups;
    for (i = 0, libslen = 0; i < libscnt; i++) {
	    if (ncp->nc_lookups[i]) {
		    libslen += strlen(ncp->nc_lookups[i]) + 1;
	    } else {
		    libslen++;
	    }
    }

    len = (sizeof(*p) + netidlen + protofmlylen + protolen + 
	   devlen + libslen + libscnt * sizeof(char *));
    p = malloc(len);
    if (!p) {
	    return NULL;
    }
    memset(p, 0, len);

    tmp = (char *)&p[1];
    if (libscnt > 0) {
	    p->nc_lookups = (char **)tmp;
	    p->nc_nlookups = libscnt;
	    tmp += libscnt * sizeof(char *);
    }
    
    p->nc_netid = tmp;
    if (ncp->nc_netid) {
	    memcpy(tmp, ncp->nc_netid, netidlen);
    }
    tmp += netidlen;

    p->nc_semantics = ncp->nc_semantics;
    p->nc_flag = ncp->nc_flag;

    p->nc_protofmly = tmp;
    if (ncp->nc_protofmly) {
	    memcpy(tmp, ncp->nc_protofmly, protofmlylen);
    }
    tmp += protofmlylen;

    p->nc_proto = tmp;
    if (ncp->nc_proto) {
	    memcpy(tmp, ncp->nc_proto, protolen);
    }
    tmp += protolen;

    p->nc_device = tmp;
    if (ncp->nc_device) {
	    memcpy(tmp, ncp->nc_device, devlen);
    }
    tmp += devlen;

    for (i = 0; i < libscnt; i++) {
	    p->nc_lookups[i] = tmp;
	    if (ncp->nc_lookups[i]) {
		    libslen = strlen(ncp->nc_lookups[i]) + 1;
		    memcpy(tmp, ncp->nc_lookups[i], libslen);
		    tmp += libslen;
	    } else {
		    tmp++;
	    }
    }

    return(p);
}

/*
 * Local Variables:
 * tab-width:8
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 *
 */
