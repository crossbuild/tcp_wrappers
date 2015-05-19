#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>

#include "ip6utils.h"

/* inet_pton_mapped() 
   - works like inet_pton(3) but always returns IPv6 address 
   in dst - either "real" or v4mapped (::ffff:1.2.3.4) in 
   the case, when src points to IPv4 address (eg. to 1.2.3.4). */
int
inet_pton_mapped (int af, const char *src, void *dst)
{
	int ret;
	
	/* Mapped address is v6. */
	if (af != AF_INET6)
	{
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* We must put the result somewhere. */
	if (!dst)
	{
		errno = EFAULT;
		return -1;
	}

	/* First try whether the address IPv6. */
	ret = inet_pton (AF_INET6, src, dst);
	if (ret > 0)
		return ret;

	/* Because we're here, it apparently wasn't IPv6. Try IPv4 now. */
	ret = inet_pton (AF_INET, src, &((struct in6_addr *)dst)->s6_addr32[3]);
	if (ret > 0)
	{
		/* Good, it was IPv4, map it now. */
		((struct in6_addr *)dst)->s6_addr32[0] = 0;
		((struct in6_addr *)dst)->s6_addr32[1] = 0;
		((struct in6_addr *)dst)->s6_addr32[2] = htonl(0x0000ffffL);
	}
	return ret;
}

/* inet_ntop2() 
   - works like inet_ntop(3) but doesn't need an external 
     buffer. Usefull eg. for printing addresses via printf(). */
const char *
inet_ntop2 (int af, const void *src)
{
	static char address[INET6_ADDRSTRLEN];
	
	return inet_ntop(af, src, address, sizeof(address));
}

/* sa_map_v4_to_v6() 
   - Take an IPv4 address in first argument and map it to 
     IPv4-mapped (::ffff:1.2.3.4) IPv6 address. */
struct sockaddr_in6 *
sa_map_v4_to_v6 (struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	/* Both pointers must be not-NULL or we'll segfault. */
	if (!sin || !sin6)
	{
		errno = EFAULT;
		return NULL;
	}
	
	/* We can map only IPv4 addresses. */
	if (sin->sin_family != AF_INET)
		return NULL;

	/* Map it now... */
	memset(sin6, 0, sizeof(*sin6));

	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.s6_addr16[5] = 0xffff;
	sin6->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;

	return sin6;
}

/* is_v4_string(), is_v6_string() 
   - Return 1 when src is a string representing a valid 
     IPv4, resp. IPv6 address.  Return 0 otherwise. */
int
is_v4_string (const char *src)
{
	struct in_addr result;
	
	return (inet_pton (AF_INET, src, &result) > 0);
}

int
is_v6_string (const char *src)
{
	struct in6_addr result;
	
	return (inet_pton (AF_INET6, src, &result) > 0);
}

/* apply_v6_prefix()
   - mask the address given in 'src' with 'prefixlen' netmask. Clear
     all bits not covered by prefixlen. */
int
apply_v6_prefix (struct in6_addr *src, int prefixlen)
{
	int i;

	/* Check prefix for a valid length. */
	if (prefixlen < 0 || prefixlen > 128)
		return -1;

	/* Prefixes will quite often end up on 16b boundary,
	   so we'll walk thorugh 16b blocks and possibly avoid 
	   creating bitmasks.  */
	for (i=0; i<8; i++)
	{
		/* Prefix fully covers this block -> leave as is. */
		if (prefixlen >= (i+1)*16)
			continue;
		/* Prefix doesn't cover this block -> zero it. */
		if (prefixlen <= i*16)
		{
			src->s6_addr16[i] = 0;
			continue;
		}
		/* Prefix ends somewhere inside in this block. Let's
		   build and apply a bitmask for this block. */
		{
			uint16_t mask=0;
			int bits;

			bits = prefixlen - i*16;

			while (bits)
			{
				mask |= (1 << (16-bits));
				bits --;
			}

			src->s6_addr16[i] &= htons(mask);
		}
	}

	return 0;
}
