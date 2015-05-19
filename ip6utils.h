#ifndef IP6UTILS_H
#define IP6UTILS_H

/* inet_pton_mapped() 
   - works like inet_pton(3) but always returns IPv6 address 
   in dst - either "real" or v4mapped (::ffff:1.2.3.4) in 
   the case, when src points to IPv4 address (eg. to 1.2.3.4). 
   Return value is as with inet_pton(), dst remains untouched on 
   an address translation failure. */
int inet_pton_mapped (int af, const char *src, void *dst);

/* inet_ntop2() 
   - works like inet_ntop(3) but doesn't need an external 
     buffer. Usefull eg. for printing addresses via printf(). */
const char *inet_ntop2 (int af, const void *src);

/* sa_map_v4_to_v6() 
   - Take an IPv4 address in form 1.2.3.4 and map it to 
     IPv4-mapped form ::ffff:1.2.3.4 */
struct sockaddr_in6 *sa_map_v4_to_v6 (struct sockaddr_in *sin, struct sockaddr_in6 *sin6);

/* is_v4_string(), is_v6_string() 
   - Return 1 when src is a string representing a valid 
     IPv4, resp. IPv6 address.  Return 0 otherwise. */
int is_v4_string (const char *src);
int is_v6_string (const char *src);

/* apply_v6_prefix()
   - mask the address given in 'src' with 'prefixlen' netmask. Clear
     all bits not covered by prefixlen. Return -1 on a failure, else 0. */
int apply_v6_prefix (struct in6_addr *src, int prefixlen);

#endif /* IP6UTILS_H */
