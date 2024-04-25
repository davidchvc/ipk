#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUFSIZE 1024
int main (int argc, const char * argv[]) {
	int client_socket, port_number, bytestx, bytesrx;
    socklen_t serverlen;
    const char *server_hostname;
    struct hostent *server;
    struct sockaddr_in server_address;
    char buf[BUFSIZE];
    char mode;
     
    if (argc != 7) {
       fprintf(stderr,"usage: %s  -h <host> -p <port> -m <mode>\n", argv[0]);
       exit(EXIT_FAILURE);
    }


    for(int i = 1;i < argc;i++)
    {
        if(strcmp("-h", argv[i])==0)
        {
            server_hostname = argv[2];
            i++;
        }
        else if (strcmp("-p", argv[i])==0)
        {
        port_number = atoi(argv[4]);
        i++;
        }
        else if (strcmp("-m", argv[i])==0)
        {
            i++;
        }
        else
        {
            fprintf(stderr,"wrong argument\n");
            exit(EXIT_FAILURE);
        }
    }

    if (server_hostname == NULL)
    {
        fprintf(stderr,"host is not specified\n");
        exit(EXIT_FAILURE);
    }

    if (port_number == 0)
    {
        fprintf(stderr,"port is not specified\n");
        exit(EXIT_FAILURE);
    }
    if (strcmp("tcp", argv[6])!=0 && strcmp("udp", argv[6])!=0)
    {
        fprintf(stderr,"wrong specification of mode\n");
        exit(EXIT_FAILURE);
    }
//cast s tcp///////////////////////////////////////////////////////////////////////////
    if (strcmp("tcp", argv[6])==0)
    {

    
    
    server = gethostbyname(server_hostname);
    if (server == NULL)
    {
        fprintf(stderr,"ERROR: no such host as %s\n", server_hostname);
        exit(EXIT_FAILURE);
    }
    
   
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number);
   
    
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket <= 0)
	{
		perror("ERROR: socket");
		exit(EXIT_FAILURE);
	}
    if (connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address)) != 0)
    {
		perror("ERROR: connect");
		exit(EXIT_FAILURE);        
    }
	    
    bzero(buf, BUFSIZE);

    while (fgets(buf, BUFSIZE , stdin) != NULL)
    {
   
    bytestx = send(client_socket, buf, strlen(buf), 0);
    if (bytestx < 0) 
    {
      perror("ERROR in sendto");
    }
    bzero(buf, BUFSIZE);
    
    bytesrx = recv(client_socket, buf, BUFSIZE, 0);
    if (bytesrx < 0) 
    {     
         perror("ERROR in recvfrom");
    }
      
    printf("%s", buf);
    }
        
    close(client_socket);
    
    }
// cast s udp//////////////////////////////////////////////////////////////
if (strcmp("udp", argv[6])==0)
{
    server = gethostbyname(server_hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR: no such host as %s\n", server_hostname);
        exit(EXIT_FAILURE);
    }
    
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number);
   
    client_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (client_socket <= 0)
	{
		perror("ERROR: socket");
		exit(EXIT_FAILURE);
	}
	    
     bzero(buf, BUFSIZE);

    while (fgets(&(buf[2]), BUFSIZE-2 , stdin) != NULL)
    {
   buf[0] = 0 ;
   //int i =2;
   /*while (&(buf[i]) != NULL)
   {
    i++;
   }*/
   
   buf[1] = strlen(buf);
   //printf("%d\n", buf[0]);
   //printf("%d\n", buf[1]);
   //printf("%d\n", buf[2]);
   //printf("%d\n", buf[3]);
   //printf("%d\n", buf[4]);
    serverlen = sizeof(server_address);
    bytestx = sendto(client_socket, buf, strlen(buf), 0, (struct sockaddr *) &server_address, serverlen);
    if (bytestx < 0) 
    {
      perror("ERROR: sendto");
    }
    bzero(buf, BUFSIZE);
    bytesrx = recvfrom(client_socket, buf, BUFSIZE, 0, (struct sockaddr *) &server_address, &serverlen);
    if (bytesrx < 0) 
    {
      perror("ERROR: recvfrom");
    }
    printf("%s", buf);
    }
    
}
return 0;
}