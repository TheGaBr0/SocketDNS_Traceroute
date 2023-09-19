#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#include <time.h>

#define MAXLEN 255
#define PORT 7777
#define ROOTDNSPORT 7778

void die(char *);
void getClientResponse(int);
void sendClientResponse(int);
void forwardToAnotherServer();
int getRoot();
void *writeToFile(char*);

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

int shmid;
char bufferInput[MAXLEN], bufferOutput[MAXLEN];

int main()
{
	memset(bufferInput, 0, MAXLEN);
	memset(bufferOutput, 0, MAXLEN);

	db *locaDatabase;
	int socketdescriptor, new_socket, pid, optval = 1, i;
	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);
	char logoutput[MAXLEN];
	bool found;
	
	FILE *file = fopen("/home/progettoreti/Desktop/progettoreti/log.txt", "a");

	if (!file) {
        perror("Errore nell'apertura del file");
        return 1;
    }

	// Creazione della memoria condivisa
	shmid = shmget(IPC_PRIVATE, sizeof(struct database), IPC_CREAT | 0666);
	if (shmid < 0)
	{
		die("shmget() error");
	}

	// Attacco del puntatore al database alla memoria condivisa
	locaDatabase = (db *)shmat(shmid, NULL, 0);
	if ((void *)locaDatabase == (void *)-1)
	{
		die("shmat() error");
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
	
	writeToFile("DNSLocale started\n");

	// Inizializzazione del database condiviso
	locaDatabase->length = 0;

	socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	if (setsockopt(socketdescriptor, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1)
	{
		perror("setsockopt");
		exit(1);
	}

	if (socketdescriptor < 0)
		die("client socket() error");

	bind_ip_port.sin_family = AF_INET;
	bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	bind_ip_port.sin_port = htons(PORT);

	if (bind(socketdescriptor, (struct sockaddr *)&bind_ip_port, bind_ip_port_length) < 0)
		die("client bind() error");

	if ((listen(socketdescriptor, 5)) != 0)
		die("client listen() error");

	
	snprintf(logoutput, sizeof(logoutput), "DNSLocale listening on port: %d\n", PORT);
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
			writeToFile("DNSLocale client accepted\n");

			if (pid = fork() == 0)
			{
				close(socketdescriptor);
				getClientResponse(new_socket);

				found = false;
				for (i = 0; i <= locaDatabase->length; i++)
				{
					//printf("%s con %s\n", bufferInput, locaDatabase->domains[i]);
					if (strcmp(bufferInput, locaDatabase->domains[i]) == 0)
					{
						strcpy(bufferOutput, locaDatabase->addresses[i]);
						found = true;
						sendClientResponse(new_socket);
					}
				}

				if (!found)
				{
					snprintf(logoutput, sizeof(logoutput), "DNSLocale didn't find the address: %s in its database\n", bufferInput);
					writeToFile(logoutput);

					forwardToAnotherServer();

					if (strcmp(bufferOutput, "NOT_EXISTS") != 0)
					{
						strcpy(locaDatabase->domains[locaDatabase->length + 1], bufferInput);
						strcpy(locaDatabase->addresses[locaDatabase->length + 1], bufferOutput);
						locaDatabase->length = locaDatabase->length + 1;
					}
					
					/*printf("domain: %s  address: %s length: %d\n", locaDatabase->domains[locaDatabase->length],
											locaDatabase->addresses[locaDatabase->length], locaDatabase->length);*/

					sendClientResponse(new_socket);
				}
				exit(0);
			}
		}
	}
	close(new_socket);
	close(socketdescriptor);
	// Rimozione della memoria condivisa
	shmctl(shmid, IPC_RMID, NULL);
	return 0;
}

void getClientResponse(int sd)
{
	int data;
	char logoutput[MAXLEN];

	data = read(sd, bufferInput, MAXLEN);

	snprintf(logoutput, sizeof(logoutput), "DNSlocale data received from client: %s\n", bufferInput);
	writeToFile(logoutput);
}

void sendClientResponse(int sd)
{	
	char logoutput[MAXLEN];
	int send;

	snprintf(logoutput, sizeof(logoutput), "DNSLocale sending response: %s to client\n", bufferOutput);
	writeToFile(logoutput);
	send = write(sd, bufferOutput, MAXLEN);
	if (send < 0)
		die("sendClientResponse send() error");
	close(sd);
}

void forwardToAnotherServer()
{
	int forward_socket, send, data;
	struct sockaddr_in server_addr;
	bool connected = false;
	char logoutput[MAXLEN];

	snprintf(logoutput, sizeof(logoutput), "DNSLocale asking for the address: %s to DNSRoot on port %d\n", bufferInput, ROOTDNSPORT);
	writeToFile(logoutput);
	while(!connected){
		// Crea il socket per la connessione al server di destinazione
		forward_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (forward_socket < 0)
			printf("forward socket() error\n");

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Indirizzo IP del server di destinazione
		server_addr.sin_port = htons(ROOTDNSPORT);

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
	snprintf(logoutput, sizeof(logoutput), "DNSLocale data received from root: %s\n", bufferOutput);
	writeToFile(logoutput);

	close(forward_socket);
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

