#include <iostream>       // std::cout
#include <thread>         // std::thread, std::this_thread::sleep_for
#include <chrono>         // std::chrono::seconds
#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <list>
#include <mutex>
#include "czr/p2p/net.h"

//#pragma  comment(lib,"ws2_32.lib")
CConnman g_conn_manager;

int main()
{
	g_conn_manager.Start();
	//std::cout << "Done spawning threads. Now waiting for them to join:\n";
	g_conn_manager.Wait();
	//std::cout << "All threads joined!\n";
	getchar();
	
	/*
	char* listen_ip = "192.168.10.129";
	int listen_port = 8888;
	int ret = netlib_init();
	if (ret == NETLIB_ERROR)
	{
		printf("netlib_init fail\n");
		return ret;
	}

	
	ret = netlib_listen(listen_ip, listen_port,http_callback, NULL);
	if (ret == NETLIB_ERROR)
	{
		printf("netlib_listen fail\n");
		return ret;
	}
	
	printf("server start listen on: %s:%d\n", listen_ip, listen_port);
	init_http_conn();
	printf("now enter the event loop...\n");

	netlib_eventloop();
	*/
	return 0;
}