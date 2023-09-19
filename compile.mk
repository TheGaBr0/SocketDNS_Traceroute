CC = gcc -w
 
all: client dnslocale dnsroot DNStld_1 DNStld_2 DNSauth_1 DNSauth_2 DNSauth_3 DNSauth_4

client: Client.c 
	${CC} -o Client Client.c
 	  
dnslocale: DNS/DNSlocale.c
	${CC} -o DNS/DNSlocale DNS/DNSlocale.c	
	
dnsroot: DNS/DNSroot.c
	${CC} -o DNS/DNSroot DNS/DNSroot.c
	
DNStld_1:	DNS/TLD/DNStld_1.c
	${CC} -o DNS/TLD/DNStld_1 DNS/TLD/DNStld_1.c
	
DNStld_2:	DNS/TLD/DNStld_2.c
	${CC} -o DNS/TLD/DNStld_2 DNS/TLD/DNStld_2.c	

DNSauth_1: DNS/AUTHORITATIVE/DNSauth_1.c
	${CC} -o DNS/AUTHORITATIVE/DNSauth_1 DNS/AUTHORITATIVE/DNSauth_1.c
	
DNSauth_2: DNS/AUTHORITATIVE/DNSauth_2.c
	${CC} -o DNS/AUTHORITATIVE/DNSauth_2 DNS/AUTHORITATIVE/DNSauth_2.c

DNSauth_3: DNS/AUTHORITATIVE/DNSauth_3.c
	${CC} -o DNS/AUTHORITATIVE/DNSauth_3 DNS/AUTHORITATIVE/DNSauth_3.c
	
DNSauth_4: DNS/AUTHORITATIVE/DNSauth_4.c
	${CC} -o DNS/AUTHORITATIVE/DNSauth_4 DNS/AUTHORITATIVE/DNSauth_4.c
	
