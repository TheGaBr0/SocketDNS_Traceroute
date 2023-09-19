#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#define MAXLEN 255
#define PORT 7779
#define NUMOFAUTH 2

void die(char *);
void getClientResponse(int, char *);
void sendClientResponse(int, char *);
void forwardToAuthServer(int, char *, char *, bool);
int getSLD(char *);
char *extractSecondLevelDomain(const char *);
int *portsDelegator();
void delegateAuthoritatives(char *, char *);
void getDelegationFromRoot(char *, int, struct sockaddr_in, int);
void fillTLDdatabase(char *);
void fillDELDatabase(char *, int);
void *writeToFile(char*);

struct delegationDB
{
	char domains[MAXLEN][MAXLEN];
	int ports[MAXLEN];
	int length;
};
typedef struct delegationDB DELdb;

struct database
{
	char domains[MAXLEN][MAXLEN];
	char addresses[MAXLEN][16];
	int length;
};
typedef struct database db;

typedef struct {
    FILE *file;
    pthread_mutex_t mutex;
} LogFile;

LogFile *data;

db TLDDatabase;
DELdb DELDatabase;
int shmid;

int main()
{

	char *bufferInput[MAXLEN], bufferOutput[MAXLEN], logoutput[MAXLEN];
	int socketdescriptor, new_socket, pid, i, serverport;
	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);

	FILE *file = fopen("/home/progettoreti/Desktop/progettoreti/log.txt", "a");

	if (!file) {
        perror("Errore nell'apertura del file");
        return 1;
    }

	shmid = shmget(IPC_PRIVATE, sizeof(LogFile), IPC_CREAT | 0666);
	if (shmid < 0)
	{
		die("shmget() error");
	}

	data = (LogFile *)shmat(shmid, NULL, 0);
	if ((void *)data == (void *)-1)
	{
		die("shmat() error");
	}

	data->file = file;
    pthread_mutex_init(&data->mutex, NULL);

	writeToFile("DNStld-1 started\n");

	srand(time(NULL));
	TLDDatabase.length=0;
	DELDatabase.length=0;

	socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	if (socketdescriptor < 0)
		die("client socket() error");

	bind_ip_port.sin_family = AF_INET;
	bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	bind_ip_port.sin_port = htons(PORT);

	if (bind(socketdescriptor, (struct sockaddr *)&bind_ip_port, bind_ip_port_length) < 0)
		die("client bind() error");

	if ((listen(socketdescriptor, 5)) != 0)
		die("client listen() error");


	snprintf(logoutput, sizeof(logoutput), "DNStld-1 listening on port: %d\n", PORT);
	writeToFile(logoutput);	

	getDelegationFromRoot(bufferInput, socketdescriptor, client_ip_port, client_ip_port_length);

	delegateAuthoritatives(bufferInput, bufferOutput);

	while (1)
	{
		new_socket = accept(socketdescriptor, (struct sockaddr *)&client_ip_port, &client_ip_port_length);

		if (new_socket < 0)
		{
			die("client accept() error");
		}
		else
		{
			writeToFile("DNStld-1 client accepted\n");

			if (pid = fork() == 0)
			{
				close(socketdescriptor);
				getClientResponse(new_socket, bufferInput);

				serverport = getSLD(bufferInput);
				if (serverport != -1)
				{
					forwardToAuthServer(serverport, bufferInput, bufferOutput, true);
				}
				else
				{
					strcpy(bufferOutput, "NOT_EXISTS");
				}

				sendClientResponse(new_socket, bufferOutput);

				exit(0);
			}
		}
	}
	close(new_socket);
	close(socketdescriptor);

	return 0;
}

void getClientResponse(int sd, char *bufferInput)
{
	int data;
	char logoutput[MAXLEN];
	data = read(sd, bufferInput, MAXLEN);
	snprintf(logoutput, sizeof(logoutput), "DNStld-1 data received from DNSRoot: %s\n", bufferInput);
	writeToFile(logoutput);
}

void sendClientResponse(int sd, char *bufferOutput)
{
	char logoutput[MAXLEN];
	int send;

	snprintf(logoutput, sizeof(logoutput), "DNStld-1 sending response to DNSRoot: %s\n", bufferOutput);
	writeToFile(logoutput);
	send = write(sd, bufferOutput, MAXLEN);

	if (send < 0)
		die("sendClientResponse send() error");
	close(sd);
}

void forwardToAuthServer(int serverport, char *bufferInput, char *bufferOutput, bool log)
{
	int forward_socket, send, data;
	struct sockaddr_in server_addr;
	bool connected = false;
	char logoutput[MAXLEN];

	if(log){
		snprintf(logoutput, sizeof(logoutput), "DNStld-1 asking for the address: %s to SLD on port %d\n", bufferInput, serverport);
		writeToFile(logoutput);
	}else{
		printf("Waiting for response from SLD, data sent %s\n", bufferInput);
	}
	
	while(!connected){
		// Crea il socket per la connessione al server di destinazione
		forward_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (forward_socket < 0)
			printf("forward socket() error\n");

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Indirizzo IP del server di destinazione
		server_addr.sin_port = htons(serverport);

		// Connessione al server di destinazione
		if (connect(forward_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) >= 0)
			connected = true;
		else
			close(forward_socket);
	}
	// Invia i dati al server di destinazione
	send = write(forward_socket, bufferInput, MAXLEN);
	if (send < 0)
		die("sendServerResponse send() error");

	// ottieni i dati dal server di destinazione
	data = read(forward_socket, bufferOutput, MAXLEN);

	if(log){
		snprintf(logoutput, sizeof(logoutput), "DNStld-1 data received from SLD: %s\n", bufferOutput);
		writeToFile(logoutput);
	}else{
		printf("Data received from SLD: %s\n", bufferOutput);
	}

	close(forward_socket);
}

int getSLD(char *bufferInput)
{
	int returnvalue = -1, i;
	char *sld = extractSecondLevelDomain(bufferInput);
	//printf("Ultima parte di '%s' -> %s\n", bufferInput, sld);

	for (i = 0; i <= DELDatabase.length; i++)
	{
		if (strcmp(sld, DELDatabase.domains[i]) == 0)
		{
			returnvalue = DELDatabase.ports[i];
		}
	}

	return returnvalue;
}

char *extractSecondLevelDomain(const char *inputString)
{
	int len, i, dotCount = 0, secondDotIndex, sldLen;
	len = strlen(inputString);
	char *sld;

	// Conta il numero di punti nella stringa
	for (i = 0; i < len; i++)
	{
		if (inputString[i] == '.')
		{
			dotCount++;
		}
	}

	// Se ci sono meno di 2 punti, restituisci NULL
	if (dotCount < 2)
	{
		return NULL;
	}

	// Cerca il secondo punto nella stringa
	secondDotIndex = -1;
	for (i = 0; i < len; i++)
	{
		if (inputString[i] == '.')
		{
			dotCount--;
			if (dotCount == 1)
			{
				secondDotIndex = i;
				break;
			}
		}
	}

	// Se il secondo punto è stato trovato, copia i caratteri successivi in una nuova stringa
	if (secondDotIndex != -1)
	{
		sldLen = len - (secondDotIndex + 1);
		sld = strdup(&inputString[secondDotIndex + 1]);
		if (sld == NULL)
		{
			perror("Errore di allocazione memoria");
			exit(EXIT_FAILURE);
		}

		return sld;
	}
	else
	{
		return NULL;
	}
}

int *portsDelegator()
{

	int *authoritativePorts = (int *)malloc(NUMOFAUTH * sizeof(int));

	int port1 = 7783;
	int port2 = 7784;

	bool randbool = rand() & 1;

	if (randbool)
	{
		authoritativePorts[0] = port1;
		authoritativePorts[1] = port2;
	}
	else
	{
		authoritativePorts[1] = port1;
		authoritativePorts[0] = port2;
	}

	return authoritativePorts;
}

void delegateAuthoritatives(char *bufferInput, char *bufferOutput)
{
	int i, j, portindex, newLength;
	const char *separator = "+";
	bool found;
	char *addr_dom_pair;

	writeToFile("DNStld-1 delegation to authoritatives started\n");

	for (i = 0; i < TLDDatabase.length; i++)
	{

		newLength = strlen(TLDDatabase.domains[i]) + strlen(separator) + strlen(TLDDatabase.addresses[i]) + 1;
		addr_dom_pair = (char *)malloc(newLength);

		snprintf(addr_dom_pair, newLength, "%s%s%s", TLDDatabase.domains[i], separator, TLDDatabase.addresses[i]);

		strcpy(bufferInput, addr_dom_pair);

		found = false;
		j = 0;
		while (!found && j < 2)
		{
			if (strcmp(extractSecondLevelDomain(TLDDatabase.domains[i]), DELDatabase.domains[j]) == 0)
			{
				portindex = j;
				found = true;
			}
			j++;
		}

		printf("Delegating %s to auth listening at port %d\n", addr_dom_pair, DELDatabase.ports[portindex]);

		forwardToAuthServer(DELDatabase.ports[portindex], bufferInput, bufferOutput, false);
	}

	strcpy(bufferInput, "INIT_COMPLETED");
	writeToFile("DNStld-1 delegation to authoritatives completed\n");
	forwardToAuthServer(DELDatabase.ports[0], bufferInput, bufferOutput, false);
	forwardToAuthServer(DELDatabase.ports[1], bufferInput, bufferOutput, false);
}

void getDelegationFromRoot(char *bufferInput, int sd, struct sockaddr_in client_ip_port, int client_ip_port_length)
{
	bool tld_db = false, del_db = false;
	int *authoritativePorts = portsDelegator(), new_socket, i, j = 0, data, send;

	writeToFile("DNStld-1 receving delegation from root\n");
	
	while (!tld_db || !del_db)
	{	
		new_socket = accept(sd, (struct sockaddr *)&client_ip_port, &client_ip_port_length);
		
		while(1){
			memset(bufferInput, 0, MAXLEN);
			data = read(new_socket, bufferInput, MAXLEN);
			
			if(data <= 0)
				break;
				
			printf("BufferInput: %s\n", bufferInput);
			if (strcmp(bufferInput, "INIT_DEL_COMPLETED") == 0)
			{
				printf("Initialization of DELDatabase completed\n");
				del_db = true;
				send = write(new_socket, "TLD-1: INIT DEL OK", MAXLEN);
				if (send < 0)
					die("address send() error");
				continue;
			}
			if (strcmp(bufferInput, "INIT_TLD_COMPLETED") == 0)
			{
				printf("Initialization of TLDDatabase completed\n");
				tld_db = true;
				send = write(new_socket, "TLD-1: INIT TLD OK", MAXLEN);
				if (send < 0)
					die("address send() error");
				continue;
			}
			
			if(!del_db){
				fillDELDatabase(bufferInput, authoritativePorts[j]);
				send = write(new_socket, "TLD-1: FILL DEL OK", MAXLEN);
				if (send < 0)
					die("address send() error");
				j++;
			}else{
				if(!tld_db){
					fillTLDdatabase(bufferInput);
					send = write(new_socket, "TLD-1: FILL TLD OK", MAXLEN);
					if (send < 0)
						die("address send() error");
				}
				
			}
		}
		close(new_socket);
	}
	writeToFile("DNStld-1 delegation completed\n");
}

void fillDELDatabase(char *bufferInput, int port)
{
	int i = DELDatabase.length;

	strcpy(DELDatabase.domains[i], bufferInput);
	DELDatabase.ports[i] = port;

	DELDatabase.length++;
}

void fillTLDdatabase(char *bufferInput)
{
	char *separator = "+";
	char *domain = strtok(bufferInput, separator);
	char *address = strtok(NULL, separator);

	int i = TLDDatabase.length;

	strcpy(TLDDatabase.domains[i], domain);
	strcpy(TLDDatabase.addresses[i], address);
	TLDDatabase.length++;
}

void die(char *error)
{

	fprintf(stderr, "%s.\n", error);
	exit(1);
}

void *writeToFile(char* string) {

	time_t currentTime;
	char timeString[30], finalString[150];
    time(&currentTime);

	printf(string);

    strftime(timeString, sizeof(timeString), "[%Y-%m-%d %H:%M:%S]", localtime(&currentTime));

    snprintf(finalString, sizeof(finalString), "%s %s", timeString, string);
    
    pthread_mutex_lock(&data->mutex); // Blocca il mutex
    fprintf(data->file, finalString);
    fflush(data->file);
    pthread_mutex_unlock(&data->mutex); // Sblocca il mutex
}
