#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<sys/socket.h>  
#include<sys/types.h>  
#include<netinet/in.h>  
#include<arpa/inet.h>  
#include <sys/fcntl.h>  
  
void select_test(int port, int backlog) {  
    int rcd;  
    int new_cli_fd;  
    int maxfd;  
    int socklen, server_len;  
    int ci;  
    int watch_fd_list[backlog + 1];  
    for (ci = 0; ci <= backlog; ci++)  
        watch_fd_list[ci] = -1;  
  
    int server_sockfd;  
    //建立socket，类型为TCP流  
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);  
    if (server_sockfd == -1) {  
        printf("create server_socket error!\n");  
        exit(1);  
    }  
  
    //设为非阻塞  
    if (fcntl(server_sockfd, F_SETFL, O_NONBLOCK) == -1) {  
        printf("Set server socket nonblock failed\n");  
        exit(1);  
    }  
  
    struct sockaddr_in server_sockaddr;  
    memset(&server_sockaddr, 0, sizeof(server_sockaddr));  
    server_sockaddr.sin_family = AF_INET;  
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);  
    //设置监听端口  
    server_sockaddr.sin_port = htons(port);  
    server_len = sizeof(server_sockaddr);  
    //绑定  
    rcd = bind(server_sockfd, (struct sockaddr *) &server_sockaddr, server_len);  
    if (rcd == -1) {  
        printf("bind port %d error!\n", ntohs(server_sockaddr.sin_port));  
        exit(1);  
    }  
    //监听  
    rcd = listen(server_sockfd, backlog);  
    if (rcd == -1) {  
        printf("listen error!\n");  
        exit(1);  
    }  
    printf("Server is  waiting on socket=%d \n", server_sockfd);  
  
    watch_fd_list[0] = server_sockfd;  
    maxfd = server_sockfd;  
  
    //初始化监听集合  
    fd_set watchset;  
    FD_ZERO(&watchset);  
    FD_SET(server_sockfd, &watchset);  
  
    struct timeval tv; /* 声明一个时间变量来保存时间 */  
    struct sockaddr_in cli_sockaddr;  
    while (1) {  
  
        tv.tv_sec = 20;  
        tv.tv_usec = 0; /* 设置select等待的最大时间为20秒*/  
        //每次都要重新设置集合才能激发事件  
        FD_ZERO(&watchset);  
        FD_SET(server_sockfd, &watchset);  
        //对已存在到socket重新设置  
        for (ci = 0; ci <= backlog; ci++)  
            if (watch_fd_list[ci] != -1) {  
                FD_SET(watch_fd_list[ci], &watchset);  
            }  
  
        rcd = select(maxfd + 1, &watchset, NULL, NULL, &tv);  
        switch (rcd) {  
        case -1:  
            printf("Select error\n");  
            exit(1);  
        case 0:  
            printf("Select time_out\n");  
            //超时则清理掉所有集合元素并关闭所有与客户端的socket  
            FD_ZERO(&watchset);  
            for (ci = 1; ci <= backlog; ci++){  
                shutdown(watch_fd_list[ci],2);  
                watch_fd_list[ci] = -1;  
            }  
            //重新设置监听socket，等待链接  
            FD_CLR(server_sockfd, &watchset);  
            FD_SET(server_sockfd, &watchset);  
            continue;  
        default:  
            //检测是否有新连接建立  
            if (FD_ISSET(server_sockfd, &watchset)) { //new connection  
                socklen = sizeof(cli_sockaddr);  
                new_cli_fd = accept(server_sockfd,  
                        (struct sockaddr *) &cli_sockaddr, &socklen);  
                if (new_cli_fd < 0) {  
                    printf("Accept error\n");  
                    exit(1);  
                }  
                printf("\nopen communication with  Client %s on socket %d\n",  
                        inet_ntoa(cli_sockaddr.sin_addr), new_cli_fd);  
  
                for (ci = 1; ci <= backlog; ci++) {  
                    if (watch_fd_list[ci] == -1) {  
                        watch_fd_list[ci] = new_cli_fd;  
                        break;  
                    }  
                }  
  
                FD_SET(new_cli_fd, &watchset);  
                if (maxfd < new_cli_fd) {  
                    maxfd = new_cli_fd;  
                }  
  
                continue;  
            } else {//已有连接的数据通信  
                //遍历每个设置过的集合元素  
                for (ci = 1; ci <= backlog; ci++) { //data  
                    if (watch_fd_list[ci] == -1)  
                        continue;  
                    if (!FD_ISSET(watch_fd_list[ci], &watchset)) {  
                        continue;  
                    }  
                    char buffer[128];  
                    //接收  
                    int len = recv(watch_fd_list[ci], buffer, 128, 0);  
                    if (len < 0) {  
                        printf("Recv error\n");  
                        exit(1);  
                    }  
                    buffer[len] = 0;  
  
                    //获得客户端的IP地址  
                    struct sockaddr_in sockaddr;  
                    getpeername(watch_fd_list[ci], (struct sockaddr*) &sockaddr,  
                            sizeof(sockaddr));  
                    printf("read data [%s] from Client %s on socket %d\n",  
                            buffer,inet_ntoa(sockaddr.sin_addr),watch_fd_list[ci]);  
                    //发送接收到到数据  
                    len = send(watch_fd_list[ci], buffer, strlen(buffer), 0);  
                    if (len < 0) {  
                        printf("Send error\n");  
                        exit(1);  
                    }  
                    printf("write data [%s] to Client %s on socket %d\n",  
                            buffer, inet_ntoa(sockaddr.sin_addr),  
                            watch_fd_list[ci]);  
  
                    shutdown(watch_fd_list[ci],2);  
                    watch_fd_list[ci] = -1;  
                    FD_CLR(watch_fd_list[ci], &watchset);  
  
                    //接收到的是关闭命令  
                    if (strcmp(buffer, "quit") == 0) {  
                        for (ci = 0; ci <= backlog; ci++)  
                            if (watch_fd_list[ci] != -1) {  
                                shutdown(watch_fd_list[ci],2);  
                            }  
                        printf("\nWeb Server Quit!\n");  
                        exit(0);  
                    }  
                }  
            }  
            break;  
        }  
    }  
}  

#define backlog   5 
const int port = 8888;

int main() 
{  
	select_test(port,backlog); 
	return 0; 
}



