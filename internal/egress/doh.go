package egress

// Well-known public DNS-over-HTTPS resolvers: the addresses their
// operators publish for their DNS service (dedicated anycast addresses,
// not shared with websites). Blocking them, plus port 853 (DNS over TLS
// and over QUIC), stops programs from resolving names past /etc/hosts
// through these resolvers. It is not complete and can't be: DoH can run
// on any HTTPS server.
var (
	DoHResolversV4 = []string{
		"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", // Cloudflare
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11", // Quad9
		"208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", // OpenDNS
		"94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", // AdGuard
	}
	DoHResolversV6 = []string{
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003",
		"2001:4860:4860::8888", "2001:4860:4860::8844",
		"2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
		"2620:119:35::35", "2620:119:53::53",
		"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
	}
	// DoHHostnames are the names browsers look up (through the system
	// resolver, so /etc/hosts applies) before switching to DoH. Sinkholed,
	// the switch fails and they keep using the system resolver.
	DoHHostnames = []string{
		"mozilla.cloudflare-dns.com", "cloudflare-dns.com", "chrome.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
		"dns.google", "dns.google.com", "8888.google",
		"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
		"doh.opendns.com", "doh.familyshield.opendns.com",
		"dns.adguard-dns.com", "dns.adguard.com", "family.adguard-dns.com",
		"dns.nextdns.io", "doh.cleanbrowsing.org", "doh.dns.sb", "dns.mullvad.net",
	}
)
