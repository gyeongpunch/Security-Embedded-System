#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>

/*
	struct sockaddr_in {
		short    sin_family;          // 주소 체계: AF_INET
		u_short  sin_port;            // 16 비트 포트 번호, network byte order
		struct   in_addr  sin_addr;   // 32 비트 IP 주소
		char     sin_zero[8];         // 전체 크기를 16 비트로 맞추기 위한 dummy
	};
*/ 

static struct sockaddr_in server_addr, client_addr;
static int server_fd, client_fd, n, n2;
static char recv_data[6000];
static char chat_data[6000];

/*
	https://pubs.opengroup.org/onlinepubs/7908799/xns/syssocket.h.html
*/

// argc -> arguments count
// argv -> arguments vector
int main(int argc, char *argv[])
{
	int len;
	char temp[20];
	printf("argc : %d\n", argc);
	
	if (argc != 2)
	{
		printf("Usage:%s <port>\n", argv[0]);
		exit(1);
	}
	
	// TCP : SOCK_STREAM
	// UDP : SCOK_DGRAM
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		printf("Server can not open socket\n");
		exit(0);
	}

	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(atoi(argv[1]));

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("Server can not bind local address\n");
		exit(0);
	}

	if (listen(server_fd, 5) < 0)
	{
		printf("Server can not listen connect\n");
		exit(0);
	}

	memset(recv_data, 0, sizeof(recv_data));
	len = sizeof(client_addr);
	printf("\n===[PORT] : %s=====\n", argv[1]);
	printf("Server waiting connection request\n");



	client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&len);

	if (client_fd < 0)
	{
		printf("Server accept failed\n");
		exit(0);
	}

	inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
	printf("%s client connect\n", temp);

	printf("\n%s(%d) entered\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

	if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
			printf("recv error\n");
			return 0;
	}
	
	json_object *token = json_tokener_parse(recv_data);
	
	printf("json : %s\n\n", json_object_get_string(token));
	
	json_object *find = json_object_object_get(token, "Name");
	printf("Name : %s\n\n", json_object_get_string(find));
	
	close(client_fd);

	close(server_fd);

	return 0;
}