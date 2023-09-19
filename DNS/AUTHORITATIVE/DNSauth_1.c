#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>


#define MAXLEN 255
#define PORT 7781

struct database{
	char domains[MAXLEN][MAXLEN];
	char addresses[MAXLEN][16];
	int length;
};
typedef struct database db;

void die(char *);
void handleResponse(int, db*, char*, short*);
void getDelegationFromTLD(db*, char*);
void *writeToFile(char*);

typedef struct {
    FILE *file;
    pthread_mutex_t mutex;
} LogFile;

LogFile *data;
int shmid;

int main()
{
	int socketdescriptor, optval=1, new_socket,pid;
	db *localDatabase;
	char logoutput[MAXLEN];
	struct sockaddr_in bind_ip_port, client_ip_port;
	short *initialize;
	FILE *file = fopen("/home/progettoreti/Desktop/progettoreti/log.txt", "a");
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);


	// Creazione della memoria condivisa
	shmid = shmget(IPC_PRIVATE, sizeof(struct database), IPC_CREAT | 0666);
	if (shmid < 0)
	{
		die("localDatabase shmget() error");
	}

	// Attacco del puntatore al database alla memoria condivisa
	localDatabase = (db *)shmat(shmid, NULL, 0);
	if ((void *)localDatabase == (void *)-1)
	{
		die("localDatabase shmat() error");
	}

	shmid = shmget(IPC_PRIVATE, MAXLEN, 0666|IPC_CREAT);
	if (shmid < 0)
	{
		die("bufferInput shmget() error");
	}

	char *bufferInput = (char*) shmat(shmid, NULL, 0);
	if ((char *)bufferInput == (void *)-1)
	{
		die("bufferInput shmat() error");
	}

	shmid = shmget(IPC_PRIVATE, sizeof(short), 0666|IPC_CREAT);
	if (shmid < 0)
	{
		die("initializedPointer shmget() error");
	}
	
	short *initialized = (short*) shmat(shmid, NULL, 0);
	if ((short *)initialized == (void *)-1)
	{
		die("initializedPointer shmat() error");
	}

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

	writeToFile("DNSauthoritative-1  started\n");

	snprintf(logoutput, sizeof(logoutput), "DNSauthoritative-1 listening on port: %d\n", PORT);
	writeToFile(logoutput);	

	socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	bind_ip_port.sin_family = AF_INET;
	bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	bind_ip_port.sin_port = htons(PORT);

	if (setsockopt(socketdescriptor, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1)
	{
		perror("setsockopt");
		exit(1);
	}

	if (socketdescriptor < 0)
		die("socket() error");

	if (bind(socketdescriptor, (struct sockaddr *)&bind_ip_port, bind_ip_port_length) < 0)
		die("bind() error");

	if ((listen(socketdescriptor, 5)) != 0)
		die("listen() error");

	localDatabase->length=0;
	*initialized = 0;

	while (1)
	{
		new_socket = accept(socketdescriptor, (struct sockaddr *)&client_ip_port, &client_ip_port_length);

		if (new_socket < 0)
		{
			die("accept() error");
		}
		else
		{
			writeToFile("DNSauthoritative-1  client accepted\n");
			if (pid = fork() == 0)
			{	
				close(socketdescriptor);
				handleResponse(new_socket, localDatabase, bufferInput, initialized);
				exit(0);
			}
		}
	}
	close(new_socket);
	close(socketdescriptor);

	return 0;
}

void handleResponse(int sd, db* localDatabase, char* bufferInput, short *initialized)
{	
	int data,send,i;
	char logoutput[MAXLEN];
	bool found;
	data = read(sd, bufferInput, MAXLEN);
	printf("BufferInput: %s\n", bufferInput);

	if(strcmp(bufferInput, "INIT_COMPLETED") == 0){
		writeToFile("DNSauthoritative-1 delegation completed\n");
		*initialized = 1;
		send = write(sd, "AUTH-1: INIT OK", MAXLEN);
		if (send < 0)
			die("address send() error");
		return;
	}

	if(!*initialized){
		writeToFile("DNSauthoritative-1 receving delegation from TLD\n");
		getDelegationFromTLD(localDatabase, bufferInput);
		send = write(sd, "AUTH-1: Entry added", MAXLEN);
		if (send < 0)
			die("address send() error");
	}
	else{
		found = false;
		snprintf(logoutput, sizeof(logoutput), "DNSauthoritative-1 data received from TLD: %s\n", bufferInput);
		writeToFile(logoutput);
		for(i = 0; i<=localDatabase->length; i++){
			if(strcmp(bufferInput, localDatabase->domains[i]) == 0){
				found = true;
				snprintf(logoutput, sizeof(logoutput), "DNSauthoritative-1 sending response to TLD: %s\n", localDatabase->addresses[i]);
				writeToFile(logoutput);
				send = write(sd, localDatabase->addresses[i], MAXLEN);
				if (send < 0)
					die("address send() error");
			}
		}
		if(!found){
			 send = write(sd, "NOT_EXISTS", MAXLEN);
			writeToFile("DNSauthoritative-1 sending response to TLD: NOT_EXISTS");
			if (send < 0)
				die("NOT_EXISTS send() error");
		}
	}
}

void getDelegationFromTLD(db* localDatabase, char* bufferInput){
	int i = localDatabase->length;
	
	char *domain,*address,*separator = "+";
	domain = strtok(bufferInput, separator);
	address = strtok(NULL, separator);

	strcpy(localDatabase->domains[i], domain);
	strcpy(localDatabase->addresses[i], address);
	localDatabase->length++;
	
}

void die(char *error)
{
	fprintf(stderr, "%s.\n", error);
	exit(1);
}


void *writeToFile(char* string) {

	time_t currentTime;
	char timeString[30],finalString[150];

    time(&currentTime);

	printf("%s", string);

    strftime(timeString, sizeof(timeString), "[%Y-%m-%d %H:%M:%S]", localtime(&currentTime));
	
    snprintf(finalString, sizeof(finalString), "%s %s", timeString, string);
    
    pthread_mutex_lock(&data->mutex); // Blocca il mutex
    fprintf(data->file, finalString);
    fflush(data->file);
    pthread_mutex_unlock(&data->mutex); // Sblocca il mutex
}
