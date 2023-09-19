#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <strings.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>

#define MAXLEN 255
#define MAXSTR 255
#define LOCALDNSPORT 7777

#define HOPSMAX 30
#define IP_MAXPACKET 65536

void die(char *);
char *callDNS(char *);
bool isFirstCharacterDigit(const char *str);
char *callEXTDNS(char *);
char *toString();
void get_dns_servers(char *str[]);
void change_to_dns_format(char *src, unsigned char *dest);
void change_to_dot_format(unsigned char *str);
void send_single_icmp(int sockfd, const char *ip, uint16_t id, uint16_t sequence, int ttl);
int wait_for_icmps(int sockfd, uint16_t pid, uint8_t ttl, struct timeval *start_time,
                   struct timeval *end_time, int nqueries);
void *writeToFile(char*);

//Struct per l'header DNS
typedef struct header {
	unsigned short id;         // Identificatore della query DNS
	unsigned char rd : 1;     // Flag per la ricorsione desiderata (1 bit)
	unsigned char tc : 1;     // Flag per la troncatura (1 bit)
	unsigned char aa : 1;     // Flag per l'autorità di risposta (1 bit)
	unsigned char opcode : 4; // Codice operativo (4 bit)
	unsigned char qr : 1;     // Flag per il tipo di query (1 bit)
	unsigned char rcode : 4;  // Codice di risposta (4 bit)
	unsigned char z : 3;      // Campo riservato (3 bit)
	unsigned char ra : 1;     // Flag per la ricorsione disponibile (1 bit)
	unsigned short qdcount;   // Numero di domande nella sezione Question (16 bit)
	unsigned short ancount;   // Numero di risposte nella sezione Answer (16 bit)
	unsigned short nscount;   // Numero di record autoritativi nella sezione Authority (16 bit)
	unsigned short arcount;   // Numero di record aggiuntivi nella sezione Additional (16 bit)
} HEADER;

//Struct per le flags della query DNS
typedef struct q_flags {
	unsigned short qtype;     // Tipo di query (16 bit)
	unsigned short qclass;    // Classe della query (16 bit)
} Q_FLAGS;

//Struct per le flags dei resource records
typedef struct rr_flags {
	unsigned short type;      // Tipo di record (16 bit)
	unsigned short class;     // Classe del record (16 bit)
	unsigned int ttl;         // Tempo di vita del record (32 bit)
	unsigned short rdlength;  // Lunghezza dei dati del record (16 bit)
} RR_FLAGS;

typedef struct {
    FILE *file;
    pthread_mutex_t mutex;
} LogFile;

LogFile data;

int main()
{	

	char sendbuff[MAXLEN], recvbuff[MAXLEN];
	char dnsoutput[MAXLEN];
	char *intCheck;
	int socketdescriptor, nqueries, ttl, i, host_reached;
	struct timeval start_time, end_time;
	u_int16_t pid;
	FILE *file = fopen("/home/progettoreti/Desktop/progettoreti/log.txt", "a");

	if (!file) {
        perror("Errore nell'apertura del file");
        return 1;
    }

	data.file = file;
    pthread_mutex_init(&data.mutex, NULL);
	
	printf("Inserisci un indirizzo ip o un nome di dominio: ");
	writeToFile("--------------------------------------\n");
	
	scanf("%s", sendbuff);

	if(isFirstCharacterDigit(sendbuff)){
		strcpy(dnsoutput, callDNS(sendbuff));

		printf("\nip dal dns simulato: %s\n", dnsoutput);
		
		if(strcmp(dnsoutput, "NOT_EXISTS") == 0){
			printf("\nContatto DNS esterno\n");
			strcpy(dnsoutput, callEXTDNS(sendbuff));
			printf("\nip dal dns esterno: %s\n", dnsoutput);
		}
	}else{
		strcpy(dnsoutput, sendbuff);
	}

	struct in_addr converted_ip;
    if (inet_pton(AF_INET, dnsoutput, &converted_ip) != 1) {
        fprintf(stderr, "IP address not valid!\nUsage: %s <IPv4 address>\n", dnsoutput);
        return EXIT_FAILURE;
    }else{
		sendbuff[strlen(sendbuff)] = '\0';
		printf("\nTraceroute to %s, %d hops max, %d byte packets\n", sendbuff, HOPSMAX, IP_MAXPACKET/8);
	}

    socketdescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketdescriptor < 0) {
        die("socket error");
    }

    pid = getpid(); 

    nqueries = 3;
    for (ttl = 1; ttl <= HOPSMAX; ttl++) {
        gettimeofday(&start_time, NULL);
        end_time = start_time;
        end_time.tv_sec++;

        for (i = 0; i < nqueries; i++) {
            send_single_icmp(socketdescriptor, dnsoutput, pid, ttl, ttl);
        }

        host_reached = wait_for_icmps(socketdescriptor, pid, ttl, &start_time, &end_time, nqueries);
        if (host_reached) {
            break;
        }
    }

	return 0;
}

void die(char *error)
{

	fprintf(stderr, "%s.\n", error);
	exit(1);
}

void *writeToFile(char* string) {

	time_t currentTime;
	char timeString[30], finalString[150];;
    time(&currentTime);
 
    strftime(timeString, sizeof(timeString), "[%Y-%m-%d %H:%M:%S]", localtime(&currentTime));

    snprintf(finalString, sizeof(finalString), "%s %s", timeString, string);
    
    pthread_mutex_lock(&data.mutex); // Blocca il mutex
    fprintf(data.file, finalString);
    fflush(data.file);
    pthread_mutex_unlock(&data.mutex); // Sblocca il mutex
}

bool isFirstCharacterDigit(const char *str) {
    if (isdigit((unsigned char)*str)) {
        return false;
    }
    return true;
}

char *callDNS(char *domain)
{
	int socketdescriptor;
	char recvbuff[MAXLEN];
	char *out;
	char *intCheck;

	struct sockaddr_in server_ip_port;
	int server_ip_port_length = sizeof(server_ip_port);

	memset(recvbuff, 0, MAXLEN);

	socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	if (socketdescriptor < 0)
		die("socket() error");

	server_ip_port.sin_family = AF_INET;
	server_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_ip_port.sin_port = htons(LOCALDNSPORT);

	if (connect(socketdescriptor, (struct sockaddr *)&server_ip_port, server_ip_port_length) < 0)
		die("Connect() error");

	if ( write(socketdescriptor, domain, MAXLEN) < 0)
		die("write() error");

	if (read(socketdescriptor, recvbuff, MAXLEN) < 0)
		die("read() error");

	out = recvbuff;
	close(socketdescriptor);
	return out;
}


char* callEXTDNS(char *domain){

	HEADER *header = NULL;
	unsigned char *qname;
	Q_FLAGS *qflags = NULL;
	unsigned char name[10][254];	
	RR_FLAGS *rrflags = NULL;
	unsigned char rdata[10][254];
	unsigned int type[10];
	unsigned char packet[65536];
	unsigned char *temp;	
	int i, j, steps = 0, ip_int[4], arrayLength, offset;
	long sock_fd;
	struct sockaddr_in servaddr;

	/* Ottengo l'indirizzo del DNS locale dal file resolv.conf */
	char **dns_addr = malloc(10 * sizeof(char *));
	for(i = 0; i < 10; ++i)
		dns_addr[i] = malloc(INET_ADDRSTRLEN);
	get_dns_servers(dns_addr);

	/* Costruzione della porzione di header del pacchetto DNS */
	header = (HEADER *)&packet;
	header->id = (unsigned short)htons(getpid());
	header->qr = 0;
	header->opcode = 0;
	header->aa = 0;
	header->tc = 0;
	header->rd = 1;
	header->ra = 0;
	header->z = 0;
	header->rcode = 0;
	header->qdcount = htons((unsigned short)(1)); //1 = numero di domini 
	header->ancount = 0x0000;
	header->nscount = 0x0000;
	header->arcount = 0x0000;

	steps = sizeof(HEADER);	

	/* Aggiunta dell'hostname immesso dall'utente nel pacchetto di query e conversione in formato DNS */
	qname = (unsigned char *)&packet[steps];
	change_to_dns_format(domain, qname);

	steps = steps + (strlen((const char *)qname) + 1);

	/* Costruzione delle flags della query nel pacchetto DNS*/
	qflags = (Q_FLAGS *)&packet[steps];
	qflags->qtype = htons(0x0001);
	qflags->qclass = htons(0x0001);

	steps = steps + sizeof(Q_FLAGS);
	
	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(53);
	inet_pton(AF_INET, dns_addr[0], &(servaddr.sin_addr));

	/* Connessione al DNS */
	connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	/* Invio del pacchetto DNS al server locale */
	write(sock_fd, (unsigned char *)packet, steps);

	/* Ricezione del pacchetto di risposta dal server locale */
	if(read(sock_fd, (unsigned char *)packet, 65536) <= 0){
		close(sock_fd);
	}
	
	for(i = 0; i < 10; ++i)
		free(dns_addr[i]);
	free(dns_addr);
	
	/* Estrazione dell'header del pacchetto di risposta */
	header = (HEADER *)&packet;
	steps = sizeof(HEADER);

	/* Estrazione del QNAME dal pacchetto di risposta */
	qname = (unsigned char *)&packet[steps];
	change_to_dot_format(qname);
	steps = steps + (strlen((const char *)qname) + 2);

	/* Estrazione delle flags dal pacchetto di risposta */
	qflags = (Q_FLAGS *)&packet[steps];
	steps = steps + sizeof(Q_FLAGS);
	
	/* Estrazione dei resource records dal pacchetto di risposta */
	for(i = 0; i < ntohs(header->ancount); ++i) {

		/* Estrazione del NAME del resource record*/		
		temp = (unsigned char *)&packet[steps];
	
		j = 0;
		while(*temp != 0) {
			if(*temp == 0xc0) {
				++temp;
				temp = (unsigned char*)&packet[*temp];
			}
			else {
				name[i][j] = *temp;
				++j;
				++temp;
			}
		}
		name[i][j] = '\0';
		steps = steps + 2;

		/* Estrazione delle flags dal resource record */
		rrflags = (RR_FLAGS *)&packet[steps];
		steps = steps + sizeof(RR_FLAGS) - 2;

		/* Estrazione dell'IPV4 dal resource record */
		if(ntohs(rrflags->type) == 1) {
			for(j = 0; j < ntohs(rrflags->rdlength); ++j)
				rdata[i][j] = (unsigned char)packet[steps + j];
			type[i] = ntohs(rrflags->type);
		}

		/* Estrazione del nome canonico resource record */
		if(ntohs(rrflags->type) == 5) {
			temp = (unsigned char *)&packet[steps];
			j = 0;
			while(*temp != 0) {
				if(*temp == 0xc0) {
					++temp;
					temp = (unsigned char*)&packet[*temp];
				}
				else {
					rdata[i][j] = *temp;
					++j;
					++temp;
				}
			}
			rdata[i][j] = '\0';
			change_to_dot_format(rdata[i]);
			type[i] = ntohs(rrflags->type);		
		}
		steps = steps + ntohs(rrflags->rdlength);
	}

	for(i = 0; i < ntohs(header->ancount); ++i) {
		if(type[i] == 1) {
			//printf("IPv4: ");
			for(j = 0; j < ntohs(rrflags->rdlength); ++j){
				ip_int[j] =  rdata[i][j];
			}
		}
	}

	//Trasformo i valori dell'ipv4 estratti in un indirizzo ip (aggiungo i punti)
	arrayLength = sizeof(ip_int) / sizeof(ip_int[0]);

    char *ipString = malloc(arrayLength * 4); // Supponendo che ogni valore richieda al massimo 3 caratteri e un punto

    offset = 0;
    for (i = 0; i < arrayLength; ++i) {
        offset += snprintf(ipString + offset, 4, "%d", ip_int[i]);
        if (i < arrayLength - 1) {
            offset += snprintf(ipString + offset, 2, ".");
        }
    }

	return ipString;
}

void get_dns_servers(char *str[]) {

	FILE *resolv_file;
	char line[100];
	int i = 0;

	resolv_file = fopen("/etc/resolv.conf", "rt");
	
	while(fgets(line, 100, resolv_file))
	{
		if(strncmp(line, "nameserver", 10) == 0) {
			strcpy(str[i], strtok(line, " "));
			strcpy(str[i], strtok(NULL, "\n"));
			++i;
		}
	}

	fclose(resolv_file);
}

//www.apple.com -> 3www5apple3com0
void change_to_dns_format(char *src, unsigned char *dest) {
	int pos = 0;
	int len = 0;
	int i;
	strcat(src, ".");
	for(i = 0; i < (int)strlen(src); ++i) {
		if(src[i] == '.') {
			dest[pos] = i - len;
			++pos;
			for(; len < i; ++len) {
				dest[pos] = src[len];
				++pos;
			}
			len++;
		}
	}
	dest[pos] = '\0';
}

//3www5apple3com0 -> www.apple.com
void change_to_dot_format(unsigned char *str) {
	int i, j;
	for(i = 0; i < strlen((const char*)str); i++) {
		unsigned int len = str[i];
		for(j = 0; j < len; j++) {
			str[i] = str[i + 1];
			++i;
		}
		str[i] = '.';
	}
	str[i - 1] = '\0';
}

static uint16_t compute_icmp_checksum(const void *buff, int length) {
    uint32_t sum;

    // Crea un puntatore costante a uint16_t che punta al buffer
    const uint16_t *ptr = buff;

    // Ciclo che calcola la somma dei valori uint16_t nel buffer
    for (sum = 0; length > 0; length -= 2)
        sum += *ptr++;

    // Aggiunge il riporto al valore somma
    sum = (sum >> 16) + (sum & 0xffff);

    // Calcola il complemento a uno della somma e restituisce il risultato
    return (uint16_t)(~(sum + (sum >> 16)));
}

void send_single_icmp(int sockfd, const char *ip, uint16_t id, uint16_t sequence, int ttl) {
    struct icmphdr icmp_header;         // Struttura per l'header ICMP
	struct sockaddr_in recipient;      // Struttura per l'indirizzo del destinatario

    icmp_header.type = ICMP_ECHO;       // Tipo di messaggio ICMP (Echo Request)
    icmp_header.code = 0;               // Codice ICMP (0 per Echo Request)
    icmp_header.un.echo.id = id;        // Identificatore ICMP
    icmp_header.un.echo.sequence = sequence; // Numero di sequenza ICMP
    icmp_header.checksum = 0;           // Inizializza il campo checksum a 0
    icmp_header.checksum = compute_icmp_checksum((uint16_t *)&icmp_header, sizeof(icmp_header)); // Calcola e imposta il checksum

    bzero(&recipient, sizeof(recipient)); // Inizializza la struttura recipient a zero
    recipient.sin_family = AF_INET;      // Famiglia di indirizzi (IPv4)
    inet_pton(AF_INET, ip, &recipient.sin_addr); // Converte l'indirizzo IP da stringa a formato binario

    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) != 0) {
        die("setsockopt error");  // Imposta il valore TTL per il socket
    }

    if (sendto(sockfd, &icmp_header, sizeof(icmp_header), 0, (struct sockaddr *)&recipient, sizeof(recipient)) < 0) {
        die("sendto() error");   // Invia il pacchetto ICMP tramite il socket
    }
}


static int time_passed(int packets_received, struct timeval *current_time, struct timeval *end_time, int nqueries) {
    if (packets_received >= nqueries || timercmp(current_time, end_time, >)) {
        return 1;
    }

    return 0;
}

int wait_for_icmps(int sockfd, uint16_t pid, uint8_t ttl, struct timeval *start_time, struct timeval *end_time, int nqueries) {
    int packets_received = 0;  
    int host_reached = 0;   
	int count = 0;

    struct timeval deltas[nqueries];  // Array per memorizzare i ritardi
    struct timeval current_time; 

    printf("%d. ", ttl);  

    gettimeofday(&current_time, NULL);  

    while (!time_passed(packets_received, &current_time, end_time, nqueries)) {
        struct sockaddr_in sender;       // Informazioni sul mittente
        socklen_t sender_len = sizeof(sender);
        uint8_t buffer[IP_MAXPACKET];    // Buffer per i dati del pacchetto

        fd_set descriptors;
        FD_ZERO(&descriptors);
        FD_SET(sockfd, &descriptors);
        struct timeval tv;
        timersub(end_time, &current_time, &tv);
        int ready = select(sockfd + 1, &descriptors, NULL, NULL, &tv);  // Verifica la disponibilità dei dati
        if (ready < 0) {
            die("select() error"); 
        } 
        if (ready == 0) {
            break;  // Esci se il timeout è scaduto
        }

        ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);  // Ricevi il pacchetto ICMP
        if (packet_len < 0) {
           die("recvfrom() error");  // Gestione dell'errore nella ricezione
        }

        gettimeofday(&current_time, NULL);  // Aggiorna il tempo corrente

        char sender_ip_str[20];
        const char *inet_ntop_ret = inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));  // Ottieni l'indirizzo IP del mittente

        struct iphdr *ip_header = (struct iphdr *) buffer;
        ssize_t ip_header_len = 4 * ip_header->ihl;  // Calcola la lunghezza dell'header IP

        struct icmphdr *icmp_ptr = (struct icmphdr *)(buffer + ip_header_len);  // Puntatore all'header ICMP

        uint8_t icmp_type = icmp_ptr->type;  // Tipo di messaggio ICMP
        int proper_type = icmp_type == ICMP_TIME_EXCEEDED || icmp_type == ICMP_ECHOREPLY;  // Verifica se il tipo è corretto

        if (icmp_type == ICMP_TIME_EXCEEDED) {
            struct iphdr *inner_ip_header = (void *) icmp_ptr + 8;  // Header IP interno (nel caso di "Time Exceeded")
            ssize_t inner_ip_header_len = 4 * inner_ip_header->ihl;
            icmp_ptr = (void *)inner_ip_header + inner_ip_header_len;  // Puntatore all'header ICMP interno
        }

        if (proper_type && icmp_ptr->un.echo.id == pid && icmp_ptr->un.echo.sequence == ttl) {
            timersub(&current_time, start_time, &deltas[packets_received]);  // Calcola il ritardo

			if(count == 0)
            	printf("\t%s ", sender_ip_str);  // Stampa l'indirizzo IP del mittente
			count++;
			
            packets_received++;  // Incrementa il conteggio dei pacchetti ricevuti
            if (icmp_type == ICMP_ECHOREPLY) {
                host_reached = 1;  // L'host è stato raggiunto se il pacchetto è di tipo "Echo Reply"
            }
        }
    }

    if (packets_received == 0) {
        printf("\t*\t*\t*");  // Nessun pacchetto ricevuto
    } else {
        for (int i = 0; i < packets_received; i++) {
            printf("\t%.1f ms", deltas[i].tv_usec / 1000.0);  // Stampa i ritardi dei pacchetti ricevuti
        }
    }

    printf("\n");

    return host_reached;  // Restituisci se l'host è stato raggiunto
}
