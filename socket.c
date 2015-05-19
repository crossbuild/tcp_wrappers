 /*
  * This module determines the type of socket (datagram, stream), the client
  * socket address and port, the server socket address and port. In addition,
  * it provides methods to map a transport address to a printable host name
  * or address. Socket address information results are in static memory.
  * 
  * The result from the hostname lookup method is STRING_PARANOID when a host
  * pretends to have someone elses name, or when a host name is available but
  * could not be verified.
  * 
  * When lookup or conversion fails the result is set to STRING_UNKNOWN.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) socket.c 1.15 97/03/21 19:27:24";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

extern char *inet_ntoa();

/* Local stuff. */

#include "tcpd.h"

/* Forward declarations. */

static void sock_sink();

#ifdef APPEND_DOT

 /*
  * Speed up DNS lookups by terminating the host name with a dot. Should be
  * done with care. The speedup can give problems with lookups from sources
  * that lack DNS-style trailing dot magic, such as local files or NIS maps.
  */

static struct hostent *gethostbyname_dot(name)
char   *name;
{
    char    dot_name[MAXHOSTNAMELEN + 1];
    struct  hostent *hp;

    /*
     * Don't append dots to unqualified names. Such names are likely to come
     * from local hosts files or from NIS.
     */

    if (strchr(name, '.') == 0 || strlen(name) >= MAXHOSTNAMELEN - 1) {
    return (gethostbyname(name));
    } else {
        sprintf(dot_name, "%s.", name);
        hp = gethostbyname(dot_name);
	if (hp)
	    return hp;
	else
	    return (gethostbyname(name));
    }
}

#define gethostbyname gethostbyname_dot
#endif

/* sock_host - look up endpoint addresses and install conversion methods */

void    sock_host(request)
struct request_info *request;
{
#ifdef INET6
    static struct sockaddr_storage client;
    static struct sockaddr_storage server;
#else
    static struct sockaddr_in client;
    static struct sockaddr_in server;
#endif
    int     len;
    char    buf[BUFSIZ];
    int     fd = request->fd;

    sock_methods(request);

    /*
     * Look up the client host address. Hal R. Brand <BRAND@addvax.llnl.gov>
     * suggested how to get the client host info in case of UDP connections:
     * peek at the first message without actually looking at its contents. We
     * really should verify that client.sin_family gets the value AF_INET,
     * but this program has already caused too much grief on systems with
     * broken library code.
     */

    len = sizeof(client);
    if (getpeername(fd, (struct sockaddr *) & client, &len) < 0) {
    request->sink = sock_sink;
    len = sizeof(client);
    if (recvfrom(fd, buf, sizeof(buf), MSG_PEEK,
             (struct sockaddr *) & client, &len) < 0) {
        tcpd_warn("can't get client address: %m");
        return;             /* give up */
    }
#ifdef really_paranoid
    memset(buf, 0 sizeof(buf));
#endif
    }
#ifdef INET6
    request->client->sin = (struct sockaddr *)&client;
#else
    request->client->sin = &client;
#endif

    /*
     * Determine the server binding. This is used for client username
     * lookups, and for access control rules that trigger on the server
     * address or name.
     */

    len = sizeof(server);
    if (getsockname(fd, (struct sockaddr *) & server, &len) < 0) {
    tcpd_warn("getsockname: %m");
    return;
    }
#ifdef INET6
    request->server->sin = (struct sockaddr *)&server;
#else
    request->server->sin = &server;
#endif
}



/* sock_hostnofd - look up endpoint addresses and install conversion methods */

void    sock_hostnofd(request)
struct request_info *request;
{
    static struct sockaddr_storage client;
    struct addrinfo hints, *res;
    int     ret;
    char    *host;

    /* If the address field is non-empty and non-unknown and if the hostname
     * field is empty or unknown, use the address field to get the sockaddr
     * and hostname. */
    if (strlen(request->client->addr) &&
	    HOSTNAME_KNOWN(request->client->addr) &&
	    (!strlen(request->client->addr) ||
		!HOSTNAME_KNOWN(request->client->name)))
	host = request->client->addr;
    else
	return;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0) {
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, NULL, &hints, &res);
    }

    if (ret != 0) {
	tcpd_warn("can't resolve hostname (%s): %s", host, gai_strerror(ret));
    } else {
	sock_methods(request);

	memcpy(&client, res->ai_addr, res->ai_addrlen);
	request->client->sin = (struct sockaddr *)&client;
	freeaddrinfo(res);

	request->client->name[0] = 0;
    }
}

/* sock_hostaddr - map endpoint address to printable form */

void    sock_hostaddr(host)
struct host_info *host;
{
#ifdef INET6
    struct sockaddr *sin = host->sin;
    char *ap;
    int alen;

    if (!sin)
        return;
    switch (sin->sa_family) {
        case AF_INET:
            ap = (char *)&((struct sockaddr_in *)sin)->sin_addr;
            alen = sizeof(struct in_addr);
            break;
        case AF_INET6:
            ap = (char *)&((struct sockaddr_in6 *)sin)->sin6_addr;
            alen = sizeof(struct in6_addr);
            break;
        default:
            return;
    }
    host->addr[0] = '\0';
    inet_ntop(sin->sa_family, ap, host->addr, sizeof(host->addr));
#else
    struct sockaddr_in *sin = host->sin;

    if (sin != 0)
    STRN_CPY(host->addr, inet_ntoa(sin->sin_addr), sizeof(host->addr));
#endif
}

#ifdef INET6
/* sock_hostname - map endpoint address to host name */
void
sock_hostname(struct host_info *host)
{
    struct addrinfo hints, *res, *resbase;
    struct sockaddr *sa = host->sin;
    struct sockaddr_in6 *sin6, sin6buf;
    int errcode;
    
    if (!sa) 
    {
            /* Unknown sockaddr => unable to verify */
            tcpd_warn ("can't verify hostname: sockaddr == NULL");
            strncpy(host->name, paranoid, sizeof(host->name));
            return;
    }

    switch (sa->sa_family)
    {
        case AF_INET:
            if (((struct sockaddr_in *)sa)->sin_addr.s_addr == 0) 
            {
                /* Address 0.0.0.0 is invalid. */
                tcpd_warn ("can't verify hostname of address %s",
                    inet_ntop2(sa->sa_family, 
                        &((struct sockaddr_in *)sa)->sin_addr));
                strncpy(host->name, paranoid, sizeof(host->name));
                return;
            }
            sin6 = sa_map_v4_to_v6 ((struct sockaddr_in *)sa, 
                    &sin6buf);
            break;
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *)sa;
            break;
        default:
            /* Unknown protocol family. */
            strncpy(host->name, paranoid, sizeof(host->name));
            return;
    }
    
    /* First resolve address to name... */
    if (getnameinfo ((struct sockaddr *)sin6, sizeof(*sin6), 
                            host->name, sizeof(host->name),
                            NULL, 0, 0) < 0)
    {
        tcpd_warn ("can't verify hostname: getnameinfo(%s): %s", 
                inet_ntop2(sin6->sin6_family, &sin6->sin6_addr),
                strerror(errno));
        strncpy(host->name, paranoid, sizeof(host->name));
        return;
    }

    /* Now resolve the name back to the address. Hopefully we'll 
       get the same one... */
    
    memset (&hints, 0, sizeof(hints));

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    
    errcode = getaddrinfo(host->name, NULL, &hints, &resbase);
    if(errcode)
    {
            tcpd_warn ("can't verify hostname: getaddrinfo(%s): %s",
                host->name,
                gai_strerror(errcode));
            strncpy(host->name, paranoid, sizeof(host->name));
            return;
    }
    
    res = resbase;
    
    /* Now walk through all reutrned addresses and see if at least one
       is the same (or mmapped-same) as the incoming one.  */
    while(res)
    {
        struct sockaddr_in6 *sin6res, sin6resbuf;
        
        switch (res->ai_family)
        {
            case AF_INET:
                sin6res = sa_map_v4_to_v6 ((struct sockaddr_in *)res->ai_addr, &sin6resbuf);
                break;
            case AF_INET6:
                sin6res = (struct sockaddr_in6 *)res->ai_addr;
                break;
            default:
                res = res->ai_next;
                continue;
        }

        if (memcmp (&sin6->sin6_addr, &sin6res->sin6_addr, 
                    sizeof(sin6->sin6_addr)) == 0)
            break;

        res = res->ai_next;
    }


    if (res == NULL)
    {
        /* We walked through the list but didn't find a matching address. */
        tcpd_warn ("can't verify hostname: getaddrinfo(%s) didn't return %s",
            host->name, 
            inet_ntop2 (sin6->sin6_family, &sin6->sin6_addr));
        strncpy(host->name, paranoid, sizeof(host->name));
	freeaddrinfo (resbase);
        return;
    }

    if ((!res->ai_canonname || STR_NE (host->name, res->ai_canonname)) && STR_NE(host->name, "localhost"))
    {
        /* We don't treat this as an error, though... */
        tcpd_warn("host name mismatch: %s != %s (%s)",
            host->name, res->ai_canonname,
            inet_ntop2 (sin6->sin6_family, &sin6->sin6_addr));
    }
    freeaddrinfo (resbase);
    return;
}
#else /* INET6 */
void sock_hostname(host)
struct host_info *host;
{
    struct sockaddr_in *sin = host->sin;
    struct hostent *hp;
    int     i;

    /*
     * On some systems, for example Solaris 2.3, gethostbyaddr(0.0.0.0) does
     * not fail. Instead it returns "INADDR_ANY". Unfortunately, this does
     * not work the other way around: gethostbyname("INADDR_ANY") fails. We
     * have to special-case 0.0.0.0, in order to avoid false alerts from the
     * host name/address checking code below.
     */
    if (sin != 0 && sin->sin_addr.s_addr != 0
    && (hp = gethostbyaddr((char *) &(sin->sin_addr),
                   sizeof(sin->sin_addr), AF_INET)) != 0) {

    STRN_CPY(host->name, hp->h_name, sizeof(host->name));

    /*
     * Verify that the address is a member of the address list returned
     * by gethostbyname(hostname).
     * 
     * Verify also that gethostbyaddr() and gethostbyname() return the same
     * hostname, or rshd and rlogind may still end up being spoofed.
     * 
     * On some sites, gethostbyname("localhost") returns "localhost.domain".
     * This is a DNS artefact. We treat it as a special case. When we
     * can't believe the address list from gethostbyname("localhost")
     * we're in big trouble anyway.
     */

    if ((hp = gethostbyname(host->name)) == 0) {

        /*
         * Unable to verify that the host name matches the address. This
         * may be a transient problem or a botched name server setup.
         */

        tcpd_warn("can't verify hostname: gethostbyname(%s) failed",
              host->name);

    } else if (STR_NE(host->name, hp->h_name)
           && STR_NE(host->name, "localhost")) {

        /*
         * The gethostbyaddr() and gethostbyname() calls did not return
         * the same hostname. This could be a nameserver configuration
         * problem. It could also be that someone is trying to spoof us.
         */

        tcpd_warn("host name/name mismatch: %s != %.*s",
              host->name, STRING_LENGTH, hp->h_name);

    } else {

        /*
         * The address should be a member of the address list returned by
         * gethostbyname(). We should first verify that the h_addrtype
         * field is AF_INET, but this program has already caused too much
         * grief on systems with broken library code.
         */

        for (i = 0; hp->h_addr_list[i]; i++) {
        if (memcmp(hp->h_addr_list[i],
               (char *) &sin->sin_addr,
               sizeof(sin->sin_addr)) == 0)
            return;         /* name is good, keep it */
        }

        /*
         * The host name does not map to the initial address. Perhaps
         * someone has messed up. Perhaps someone compromised a name
         * server.
         */

        tcpd_warn("host name/address mismatch: %s != %.*s",
              inet_ntoa(sin->sin_addr), STRING_LENGTH, hp->h_name);
    }
    strcpy(host->name, paranoid);       /* name is bad, clobber it */
    }
}
#endif /* INET6 */

/* sock_sink - absorb unreceived IP datagram */

static void sock_sink(fd)
int     fd;
{
    char    buf[BUFSIZ];
#ifdef INET6
    struct sockaddr_storage sin;
#else
    struct sockaddr_in sin;
#endif
    int     size = sizeof(sin);

    /*
     * Eat up the not-yet received datagram. Some systems insist on a
     * non-zero source address argument in the recvfrom() call below.
     */

    (void) recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) & sin, &size);
}
