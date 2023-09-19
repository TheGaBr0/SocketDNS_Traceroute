#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#include <time.h>

#define MAXLEN 255
#define LOCALDNSPORT 7778
#define NUMOFTLD 2

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

void die(char *);
void getClientResponse(int,  char* );
void sendClientResponse(int,  char* );
void forwardToTLDServer(int,  char* ,  char*, bool);
void extractFirstLevelDomain(const char *, char *);
int getTLD(DELdb,  char* );
void delegateTLD(DELdb, db, char *, char *);
int *portsDelegator();
char **getUniqueSecondLevelDomains(char **, int, int *);
char *extractSecondLevelDomain(const char *);
void *writeToFile(char*);

int shmid;

int main()
{
	char bufferInput[MAXLEN], bufferOutput[MAXLEN],	logoutput[MAXLEN];
	int socketdescriptor, new_socket, pid, serverport;

	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);

	bind_ip_port.sin_family = AF_INET;
	bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	bind_ip_port.sin_port = htons(LOCALDNSPORT);

		db TLDDatabase = {
	// Inizializzazione del primo array di stringhe
	{
		"www.wikipedia.org",
		"it.wikipedia.org",
		"www.un.org",
		"it.un.org",
		"www.google.it",
		"ftp.google.it",
		"unimia.unimi.it",
		"ariel.unimi.it"
	},
	// Inizializzazione del secondo array di stringhe
	{
		"185.15.58.224",
		"185.15.58.224",
		"185.15.58.224",
		"192.168.1.4",
		"185.15.58.224",
		"192.168.1.6",
		"159.149.53.172",
		"103.224.182.250"
	},
	.length = 7
	};

	srand(time(NULL));
	int *tldPorts = portsDelegator();

	DELdb DELDatabase = {
		// Inizializzazione del primo array di stringhe
		{
			"it",
			"org",
		},
		// Inizializzazione del secondo array di stringhe
		{
			tldPorts[0],
			tldPorts[1],
		},
		.length = 1
	};

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
	
	writeToFile("DNSRoot started\n");


	delegateTLD(DELDatabase, TLDDatabase, bufferInput, bufferOutput);

	socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	if (socketdescriptor < 0)
		die("client socket() error");

	if (bind(socketdescriptor, (struct sockaddr *)&bind_ip_port, bind_ip_port_length) < 0)
		die("client bind() error");

	if ((listen(socketdescriptor, 5)) != 0)
		die("client listen() error");
	snprintf(logoutput, sizeof(logoutput), "DNSRoot listening on port: %d\n", LOCALDNSPORT);
	writeToFile(logoutput);
	while (1)
	{
		new_socket = accept(socketdescriptor, (struct sockaddr *)&client_ip_port, &client_ip_port_length);

		if (new_socket < 0)
		{
			die("client accept() error");
		}
		else
		{
			writeToFile("DNSRoot client accepted\n");

			if (pid = fork() == 0)
			{
				close(socketdescriptor);
				getClientResponse(new_socket, bufferInput);
				
				serverport = getTLD(DELDatabase, bufferInput);
				if (serverport != -1)
				{
					forwardToTLDServer(serverport, bufferInput, bufferOutput, true);
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

void getClientResponse(int sd, char* bufferInput)
{
	char logoutput[MAXLEN];
	int data = read(sd, bufferInput, MAXLEN);
	snprintf(logoutput, sizeof(logoutput), "DNSRoot data received from DNSLocale: %s\n", bufferInput);
	writeToFile(logoutput);

}

void sendClientResponse(int sd, char* bufferOutput)
{
	char logoutput[MAXLEN];
	int send;
	snprintf(logoutput, sizeof(logoutput), "DNSRoot sending response: %s to DNSLocale\n", bufferOutput);
	writeToFile(logoutput);
	send = write(sd, bufferOutput, MAXLEN);
	if (send < 0)
		die("sendClientResponse send() error");
	close(sd);
}

void forwardToTLDServer(int serverport, char* bufferInput, char* bufferOutput, bool log)
{
	int forward_socket,send,data;
	struct sockaddr_in server_addr;
	bool connected = false;
	char logoutput[MAXLEN];
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Indirizzo IP del server di destinazione
	server_addr.sin_port = htons(serverport);

	if(log){
		snprintf(logoutput, sizeof(logoutput), "DNSRoot asking for the address: %s to TLD on port %d\n", bufferInput, serverport);
		writeToFile(logoutput);
	}else{
		printf("Waiting for response from TLD, data sent %s\n", bufferInput);
	}

	while(!connected){
		// Crea il socket per la connessione al server di destinazione
		forward_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (forward_socket < 0)
			printf("forward socket() error\n");

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
		snprintf(logoutput, sizeof(logoutput), "DNSRoot data received from TLD: %s\n", bufferOutput);
		writeToFile(logoutput);
	}else{
		printf("Data received from TLD: %s\n", bufferOutput);
	}
	

	close(forward_socket);
}

int getTLD(DELdb DELDatabase, char* bufferInput)
{
	char result[MAXLEN];
	int returnvalue = -1,i;
	
	extractFirstLevelDomain(bufferInput, result);
	
	// printf("Ultima parte di '%s' -> %s\n", bufferInput, result);
	
	for ( i = 0; i <= DELDatabase.length; i++)
	{
		if (strcmp(result, DELDatabase.domains[i]) == 0)
		{
			returnvalue = DELDatabase.ports[i];
		}
	}

	return returnvalue;
}

void extractFirstLevelDomain(const char *str, char *result)
{
	int len = strlen(str),lastDotIndex = -1,i;

	// Trova l'indice dell'ultimo punto nella stringa
	for (i = 0; i < len; i++)
	{
		if (str[i] == '.')
		{
			lastDotIndex = i;
		}
	}

	// Se è stato trovato un punto, estrae la parte successiva dopo l'ultimo punto
	if (lastDotIndex != -1)
	{
		strcpy(result, str + lastDotIndex + 1);
	}
	else
	{
		// Se non è presente alcun punto, restituisce l'intera stringa originale
		strcpy(result, str);
	}
}

char *extractSecondLevelDomain(const char *inputString)
{
	int len = strlen(inputString), dotCount = 0, i,secondDotIndex,sldLen;
	char *sld;

	secondDotIndex = -1;

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

char **getUniqueSecondLevelDomains(char *inputArray[], int arraySize, int *uniqueCount) {
    char **uniqueDomains = NULL;
	char *sld;
	int i,j, isDuplicate;
    *uniqueCount = 0;

    for (i = 0; i < arraySize; i++) {
        sld = extractSecondLevelDomain(inputArray[i]);
        if (sld) {
            isDuplicate = 0;
            for (j = 0; j < *uniqueCount; j++) {
                if (strcmp(uniqueDomains[j], sld) == 0) {
                    isDuplicate = 1;
                    break;
                }
            }
            
            if (!isDuplicate) {
                (*uniqueCount)++;
                uniqueDomains = realloc(uniqueDomains, sizeof(char *) * (*uniqueCount));
                uniqueDomains[*uniqueCount - 1] = sld;
            } else {
                free(sld); // Liberiamo la memoria della stringa duplicata
            }
        }
    }

    return uniqueDomains;
}

int *portsDelegator()
{

	int *authoritativePorts = (int *)malloc(NUMOFTLD* sizeof(int));

	int port1 = 7779;
	int port2 = 7780;

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

void delegateTLD(DELdb DELdatabase, db database, char *bufferInput, char *bufferOutput)
{	
	char logoutput[MAXLEN],result[MAXLEN];
	char **uniqueDomains;
	int i, j, portindex, uniqueCount = 0,arraySize, newLength;
	char *inputArray[MAXLEN] /* Array di puntatori a caratteri*/ ,*addr_dom_pair; 
	bool found;

	writeToFile("DNSRoot delegation to TLD started\n");
	

    for (i = 0; i < MAXLEN; i++) {
        inputArray[i] = strdup(database.domains[i]); // Copia la stringa nell'array di puntatori
        if (inputArray[i] == NULL) {
            perror("Errore di allocazione memoria");
            return 1;
        }
    }

	arraySize = sizeof(inputArray) / sizeof(inputArray[0]);
    uniqueDomains = getUniqueSecondLevelDomains(inputArray, arraySize, &uniqueCount);

	for (i = 0; i < uniqueCount; i++)
	{	
		found = false;
		j = 0;
		while (!found && j < 2)
		{
			extractFirstLevelDomain(uniqueDomains[i], result);
			if (strcmp(result, DELdatabase.domains[j]) == 0)
			{
				portindex = j;
				found = true;
			}
			j++;
		}

		printf("Delegating %s to TLD listening at port %d\n", uniqueDomains[i], DELdatabase.ports[portindex]);

		strcpy(bufferInput, uniqueDomains[i]);

		forwardToTLDServer(DELdatabase.ports[portindex], bufferInput, bufferOutput, false);
	}

	strcpy(bufferInput, "INIT_DEL_COMPLETED");
	
	forwardToTLDServer(DELdatabase.ports[0], bufferInput, bufferOutput, false);
	forwardToTLDServer(DELdatabase.ports[1], bufferInput, bufferOutput, false);

	for (i = 0; i <= database.length; i++)
	{
		newLength = strlen(database.domains[i]) + strlen("+") + strlen(database.addresses[i]) + 1;
		addr_dom_pair = (char *)malloc(newLength);

		snprintf(addr_dom_pair, newLength, "%s%s%s", database.domains[i], "+", database.addresses[i]);

		strcpy(bufferInput, addr_dom_pair);

		found = false;
		j = 0;
		while (!found && j < 2)
		{
			extractFirstLevelDomain(database.domains[i], result);
			if (strcmp(result, DELdatabase.domains[j]) == 0)
			{
				portindex = j;
				found = true;
			}
			j++;
		}

		printf("Filling %s to tld's database listening at port %d\n", addr_dom_pair, DELdatabase.ports[portindex]);

		forwardToTLDServer(DELdatabase.ports[portindex], bufferInput, bufferOutput, false);
	}

	strcpy(bufferInput, "INIT_TLD_COMPLETED");
	forwardToTLDServer(DELdatabase.ports[0], bufferInput, bufferOutput, false);
	forwardToTLDServer(DELdatabase.ports[1], bufferInput, bufferOutput, false);
	writeToFile("DNSRoot delegation to TLD completed\n");
}

void die(char *error)
{

	fprintf(stderr, "%s.\n", error);
	exit(1);
}

void *writeToFile(char* string) {

	time_t currentTime;
    time(&currentTime);

	printf(string);

	char timeString[30], finalString[150];
    strftime(timeString, sizeof(timeString), "[%Y-%m-%d %H:%M:%S]", localtime(&currentTime));
    snprintf(finalString, sizeof(finalString), "%s %s", timeString, string);
    
    pthread_mutex_lock(&data->mutex); // Blocca il mutex
    fprintf(data->file, finalString);
    fflush(data->file);
    pthread_mutex_unlock(&data->mutex); // Sblocca il mutex
}
