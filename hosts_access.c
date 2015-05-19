 /*
  * This module implements a simple access control language that is based on
  * host (or domain) names, NIS (host) netgroup names, IP addresses (or
  * network numbers) and daemon process names. When a match is found the
  * search is terminated, and depending on whether PROCESS_OPTIONS is defined,
  * a list of options is executed or an optional shell command is executed.
  * 
  * Host and user names are looked up on demand, provided that suitable endpoint
  * information is available as sockaddr_in structures or TLI netbufs. As a
  * side effect, the pattern matching process may change the contents of
  * request structure fields.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Compile with -DNETGROUP if your library provides support for netgroups.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) hosts_access.c 1.21 97/02/12 02:13:22";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#ifdef INET6
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <string.h>
#include <rpcsvc/ypclnt.h>

extern char *fgets();
extern int errno;

#ifndef	INADDR_NONE
#define	INADDR_NONE	(-1)		/* XXX should be 0xffffffff */
#endif

/* Local stuff. */

#include "tcpd.h"

/* Error handling. */

extern jmp_buf tcpd_buf;

/* Delimiters for lists of daemons or clients. */

static char sep[] = ", \t\r\n";

/* Constants to be used in assignments only, not in comparisons... */

#define	YES		1
#define	NO		0
#define	ERR		-1

 /*
  * These variables are globally visible so that they can be redirected in
  * verification mode.
  */

char   *hosts_allow_table = HOSTS_ALLOW;
char   *hosts_deny_table = HOSTS_DENY;
int     hosts_access_verbose = 0;

 /*
  * In a long-running process, we are not at liberty to just go away.
  */

int     resident = (-1);		/* -1, 0: unknown; +1: yes */

/* Forward declarations. */

static int table_match();
static int list_match();
static int server_match();
static int client_match();
static int host_match();
static int string_match();

/* Size of logical line buffer. */

#define	BUFLEN 2048

/* hosts_access - host access control facility */

int
yp_get_default_domain (char **outdomain)
{
  static char __ypdomainname[1025] = "\0";
  int result = YPERR_SUCCESS;;
  *outdomain = NULL;

  if (__ypdomainname[0] == '\0')
    {
      if (getdomainname (__ypdomainname, 1024))
        result = YPERR_NODOM;
      else if (strcmp (__ypdomainname, "(none)") == 0)
        {
          /* If domainname is not set, some Systems will return "(none)" */
          __ypdomainname[0] = '\0';
          result = YPERR_NODOM;
        }
      else
        *outdomain = __ypdomainname;
    }
  else
    *outdomain = __ypdomainname;

  return result;
}


int     hosts_access(request)
struct request_info *request;
{
    int     verdict;
    /*
     * If the (daemon, client) pair is matched by an entry in the file
     * /etc/hosts.allow, access is granted. Otherwise, if the (daemon,
     * client) pair is matched by an entry in the file /etc/hosts.deny,
     * access is denied. Otherwise, access is granted. A non-existent
     * access-control file is treated as an empty file.
     * 
     * After a rule has been matched, the optional language extensions may
     * decide to grant or refuse service anyway. Or, while a rule is being
     * processed, a serious error is found, and it seems better to play safe
     * and deny service. All this is done by jumping back into the
     * hosts_access() routine, bypassing the regular return from the
     * table_match() function calls below.
     */

    if (resident <= 0)
	resident++;
    verdict = setjmp(tcpd_buf);
    if (verdict != 0)
	return (verdict == AC_PERMIT);
    if (table_match(hosts_allow_table, request) == YES)
	return (YES);
    if (table_match(hosts_deny_table, request) == NO)
	return (YES);
    return (NO);
}

/* table_match - match table entries with (daemon, client) pair */

static int table_match(table, request)
char   *table;
struct request_info *request;
{
    FILE   *fp;
    char    sv_list[BUFLEN];		/* becomes list of daemons */
    char   *cl_list;			/* becomes list of clients */
    char   *sh_cmd;			/* becomes optional shell command */
    int     match = NO;
    struct tcpd_context saved_context;

    saved_context = tcpd_context;		/* stupid compilers */

    /*
     * Between the fopen() and fclose() calls, avoid jumps that may cause
     * file descriptor leaks.
     */

    if ((fp = fopen(table, "re")) != 0) {
	tcpd_context.file = table;
	tcpd_context.line = 0;
	while (match == NO && xgets(sv_list, sizeof(sv_list), fp) != 0) {
	    if (sv_list[strlen(sv_list) - 1] != '\n') {
		tcpd_warn("missing newline or line too long");
		continue;
	    }
	    if (sv_list[0] == '#' || sv_list[strspn(sv_list, " \t\r\n")] == 0)
		continue;
	    if ((cl_list = split_at(sv_list, ':')) == 0) {
		tcpd_warn("missing \":\" separator");
		continue;
	    }
	    sh_cmd = split_at(cl_list, ':');
	    match = list_match(sv_list, request, server_match)
		&& list_match(cl_list, request, client_match);
	}
	(void) fclose(fp);
    } else if (errno != ENOENT) {
	tcpd_warn("cannot open %s: %m", table);
	match = ERR;
    }
    if (match == YES) {
	if (hosts_access_verbose > 1)
	    syslog(LOG_DEBUG, "matched:  %s line %d",
		   tcpd_context.file, tcpd_context.line);
	if (sh_cmd) {
#ifdef PROCESS_OPTIONS
	    process_options(sh_cmd, request);
#else
	    char    cmd[BUFSIZ];
	    shell_cmd(percent_x(cmd, sizeof(cmd), sh_cmd, request));
#endif
	}
    }
    tcpd_context = saved_context;
    return (match);
}

/* list_match - match a request against a list of patterns with exceptions */

static int list_match(list, request, match_fn)
char   *list;
struct request_info *request;
int   (*match_fn) ();
{
    char   *tok;

    /*
     * Process tokens one at a time. We have exhausted all possible matches
     * when we reach an "EXCEPT" token or the end of the list. If we do find
     * a match, look for an "EXCEPT" list and recurse to determine whether
     * the match is affected by any exceptions.
     */

    for (tok = strtok(list, sep); tok != 0; tok = strtok((char *) 0, sep)) {
	if (STR_EQ(tok, "EXCEPT"))		/* EXCEPT: give up */
	    return (NO);
	if (match_fn(tok, request)) {		/* YES: look for exceptions */
	    while ((tok = strtok((char *) 0, sep)) && STR_NE(tok, "EXCEPT"))
		 /* VOID */ ;
	    return (tok == 0 || list_match((char *) 0, request, match_fn) == 0);
	}
    }
    return (NO);
}

/* server_match - match server information */

static int server_match(tok, request)
char   *tok;
struct request_info *request;
{
    char   *host;

    if ((host = split_at(tok + 1, '@')) == 0) {	/* plain daemon */
	return (string_match(tok, eval_daemon(request)));
    } else {					/* daemon@host */
	return (string_match(tok, eval_daemon(request))
		&& host_match(host, request->server));
    }
}

/* client_match - match client information */

static int client_match(tok, request)
char   *tok;
struct request_info *request;
{
    char   *host;

    if ((host = split_at(tok + 1, '@')) == 0) {	/* plain host */
	return (host_match(tok, request->client));
    } else {					/* user@host */
	return (host_match(host, request->client)
		&& string_match(tok, eval_user(request)));
    }
}

/* hostfile_match - look up host patterns from file */

static int hostfile_match(path, host)
char   *path;
struct hosts_info *host;
{
    char    tok[BUFSIZ];
    int     match = NO;
    FILE   *fp;

    if ((fp = fopen(path, "re")) != 0) {
	while (fscanf(fp, "%s", tok) == 1 && !(match = host_match(tok, host)))
	     /* void */ ;
	fclose(fp);
    } else if (errno != ENOENT) {
	tcpd_warn("open %s: %m", path);
    }
    return (match);
}

/* host_match - match host name and/or address against pattern */

static int host_match(tok, host)
char   *tok;
struct host_info *host;
{
    char   *mask;

    /*
     * This code looks a little hairy because we want to avoid unnecessary
     * hostname lookups.
     * 
     * The KNOWN pattern requires that both address AND name be known; some
     * patterns are specific to host names or to host addresses; all other
     * patterns are satisfied when either the address OR the name match.
     */

    if (tok[0] == '@') {			/* netgroup: look it up */
#ifdef  NETGROUP
	static char *mydomain = 0;
	if (mydomain == 0)
	    yp_get_default_domain(&mydomain);
	return (innetgr(tok + 1, eval_hostname(host), (char *) 0, mydomain));
#else
	tcpd_warn("netgroup support is disabled");	/* not tcpd_jump() */
	return (NO);
#endif
    } else if (tok[0] == '/') {			/* /file hack */
	return (hostfile_match(tok, host));
    } else if (STR_EQ(tok, "KNOWN")) {		/* check address and name */
	char   *name = eval_hostname(host);
	return (STR_NE(eval_hostaddr(host), unknown) && HOSTNAME_KNOWN(name));
    } else if (STR_EQ(tok, "LOCAL")) {		/* local: no dots in name */
	char   *name = eval_hostname(host);
	return (strchr(name, '.') == 0 && HOSTNAME_KNOWN(name));
    } else {					/* anything else */
	return (string_match(tok, eval_hostaddr(host))
	    || (NOT_INADDR(tok) && string_match(tok, eval_hostname(host))));
    }
}

/* string_match - match string against pattern 
 * 
 * tok = data read from /etc/hosts.*
 * string = textual data of actual client
 */

static int string_match(tok, string)
char   *tok;
char   *string;
{
    int     n;

#ifndef DISABLE_WILDCARD_MATCHING
    if (strchr(tok, '*') || strchr(tok,'?')) {  /* contains '*' or '?' */
        return (match_pattern_ylo(string,tok));
    } else
#endif

    if (tok[0] == '.') {			/* suffix */
	n = strlen(string) - strlen(tok);
	return (n > 0 && STR_EQ(tok, string + n));
    } else if (STR_EQ(tok, "ALL")) {		/* all: match any */
	return (YES);
    } else if (STR_EQ(tok, "KNOWN")) {		/* not unknown */
	return (STR_NE(string, unknown));
    } else if (STR_EQ(tok, string))		/* exact match */
	return (YES);
#ifdef INET6
    else	/* IP addresses match - not needed for IPv4 */
    {
	/* For simplicity we convert everything to IPv6 (or v4 mapped) */
	struct in6_addr pat, addr;
	int len, ret, prefixlen=128, nof_periods = 0;
	char ch, token[INET6_ADDRSTRLEN+1], *mask, *ptok = tok, *addition;
	len = strlen(tok);
	if (tok[(n = strlen(tok)) - 1] == '.') {	/* prefix */
	  while ((ptok = strchr(ptok, '.')) != NULL){
	    nof_periods++;
	    ptok++;
	  }
	  switch(nof_periods){
	  case 1:
	    addition = "0.0.0/8";
	    break;
	  case 2:
	    addition = "0.0/16";
	    break;
	  case 3:
	    addition = "0/24";
	    break;
	  default: 
	    tcpd_warn ("Wrong prefix %s", tok);
	    return (NO);
	  }
	  snprintf(token, sizeof(token), "%s%s", tok, addition);
	}	
	else if (*tok == '[' && tok[len - 1] == ']') 
	{
		ch = tok[len - 1];
			tok[len - 1] = '\0';
			snprintf(token, sizeof(token), "%s", tok+1);
			tok[len - 1] = ch;
	}
	else
		snprintf(token, sizeof(token), "%s", tok);
	
	/* If prefix was given, handle it */
	if ((mask = split_at(token, '/')) != 0)
	{
		if (strchr(mask, '.') != NULL) /* We have something
                                                  like 255.255.0.0  */
                {
		   int b1, b2, b3, b4;
		   uint32_t netmask;

		   if (sscanf(mask, "%d.%d.%d.%d", &b1, &b2, &b3, &b4) != 4)
		   {
			tcpd_warn ("Wrong netmask in %s", tok);
			return (NO);
		   }
		   netmask = (((((b1 * 256) + b2) * 256) + b3) * 256) + b4;
		   prefixlen = 0;
		   while (netmask > 0)
		   {
			++prefixlen;
			netmask  <<= 1;
                   }
                }
		else if (sscanf(mask, "%d", &prefixlen) != 1 || prefixlen < 0)
		{
			tcpd_warn ("Wrong prefix length in %s", tok);
			return (NO);
		}
		
		if (is_v4_string (token))
			prefixlen += 96;	/* extend to v4mapped */

		if (prefixlen > 128)
		{
			tcpd_warn ("Prefix too long in %s", tok);
			return (NO);
		}
	}
	
	memset (&pat, 0, sizeof(pat));
	memset (&addr, 0, sizeof(addr));

	if (inet_pton_mapped(AF_INET6, token, &pat) != 1)
		return (NO);

	if (inet_pton_mapped(AF_INET6, string, &addr) != 1)
	{
		tcpd_warn("Unable to handle client address: %s", string);
		return (NO);
	}

	if (prefixlen < 128)
	{
		apply_v6_prefix (&pat, prefixlen);
		apply_v6_prefix (&addr, prefixlen);
	}

	return (!memcmp(&pat, &addr, sizeof(struct in6_addr)));
    }
#endif
}

#ifndef DISABLE_WILDCARD_MATCHING
/* Note: this feature has been adapted in a pretty straightforward way
   from Tatu Ylonen's last SSH version under free license by
   Pekka Savola <pekkas@netcore.fi>.

   Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
*/

/* Returns true if the given string matches the pattern (which may contain
   ? and * as wildcards), and zero if it does not match. */

int match_pattern_ylo(const char *s, const char *pattern)
{
  while (1)
    {
      /* If at end of pattern, accept if also at end of string. */
      if (!*pattern)
        return !*s;

      /* Process '*'. */
      if (*pattern == '*')
        {
	  /* Skip the asterisk. */
	  pattern++;

	  /* If at end of pattern, accept immediately. */
          if (!*pattern)
            return 1;

	  /* If next character in pattern is known, optimize. */
          if (*pattern != '?' && *pattern != '*')
            {
	      /* Look instances of the next character in pattern, and try
		 to match starting from those. */
              for (; *s; s++)
                if (*s == *pattern &&
                    match_pattern_ylo(s + 1, pattern + 1))
                  return 1;
	      /* Failed. */
              return 0;
            }

	  /* Move ahead one character at a time and try to match at each
	     position. */
          for (; *s; s++)
            if (match_pattern_ylo(s, pattern))
              return 1;
	  /* Failed. */
          return 0;
        }

      /* There must be at least one more character in the string.  If we are
	 at the end, fail. */
      if (!*s)
        return 0;

      /* Check if the next character of the string is acceptable. */
      if (*pattern != '?' && *pattern != *s)
	return 0;

      /* Move to the next character, both in string and in pattern. */
      s++;
      pattern++;
    }
  /*NOTREACHED*/
}
#endif /* DISABLE_WILDCARD_MATCHING */
