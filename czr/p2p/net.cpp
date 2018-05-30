#include "net.h"
#include "sync.h"
#include "netaddress.h"
#include "protocol.h"
#include "threadinterrupt.h"
#include "util.h"
#include "netbase.h"
#include "net_process.h"
#include <algorithm>
#include <iostream>
#include <vector>

void CNode::CloseSocketDisconnect()
{
	fDisconnect = true;
	LOCK(cs_hSocket);
	if (hSocket != INVALID_SOCKET)
	{
		//LogPrint(BCLog::NET, "disconnecting peer=%d\n", id);
		CloseSocket(hSocket);
	}
}

bool CNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool& complete)
{
	return true;
}


//连接管理类开始
void CConnman::Start()
{
	if (semAddnode == nullptr) {
		// initialize semaphore
		semAddnode = MakeUnique<CSemaphore>(nMaxAddnode);
	}
	
	//m_msgproc = new PeerLogicValidation(this);
	//threadSocketHandler = std::thread(std::function<void()>(std::bind(&CConnman::ThreadSocketHandler, this)));//socket收发句柄，接受连接

	//threadOpenConnections = std::thread(std::function<void()>(std::bind(&CConnman::ThreadOpenConnections, this)));//打开连接线程

	//threadMessageHandler = std::thread(std::function<void()>(std::bind(&CConnman::ThreadMessageHandler, this)));//打开消息处理
	

	CConnman::Options connOptions;
	m_msgproc = new PeerLogicValidation(this);
	threadSocketHandler = std::thread(&TraceThread<std::function<void()> >, "net", std::function<void()>(std::bind(&CConnman::ThreadSocketHandler, this)));

	//threadMessageHandler = std::thread(&TraceThread<std::function<void()> >, "msghand", std::function<void()>(std::bind(&CConnman::ThreadMessageHandler, this)));
	
	threadOpenConnections = std::thread(&TraceThread<std::function<void()> >, "opencon", std::function<void()>(std::bind(&CConnman::ThreadOpenConnections, this, connOptions.m_specified_outgoing)));

}

void CConnman::Stop()
{

}
void CConnman::Wait()
{
	//threadDNSAddressSeed.join();

	//threadSocketHandler.join();

	//threadOpenAddedConnections.join();

	threadOpenConnections.join();

	//threadMessageHandler.join();
}

bool CConnman::InitAndListern(SOCKET &sListen, uint16_t port)
{
	WSADATA wsaData;
	sockaddr_in local;
	WORD version = MAKEWORD(2, 0);
	int ret = WSAStartup(version, &wsaData);
	if (ret != 0)
	{
		printf("WSAStarup failed\n");
		return 0;
	}
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons((u_short)port);

	sListen = socket(AF_INET, SOCK_STREAM, 0);
	if (sListen == INVALID_SOCKET)
	{
		printf("Initial socket failed\n");
		return 0;
	}

	if (bind(sListen, (sockaddr*)&local, sizeof(local)) != 0)
	{
		printf("Bind socket failed\n");
		return 0;
	}

	if (listen(sListen, 10) != 0)
	{
		printf("Listen socket failed\n");
		return 0;
	}
	return 1;
}

int CConnman::ConnectRemoteSocket(const char *serIP, unsigned short serPort,int *connSock)
{
	WSADATA wsaData;
	sockaddr_in local;
	WORD version = MAKEWORD(2, 0);
	int ret = WSAStartup(version, &wsaData);
	if (ret != 0)
	{
		printf("WSAStarup failed\n");
		return -1;
	}
	//创建socket  
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		printf("socket Error!");
		return -1;
	}

	//填充sockaddr_in  
	struct sockaddr_in serAddr;
	memset(&serAddr, 0, sizeof(serAddr));
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(serPort);
	//int rtn = inet_pton(AF_INET, serIP, &serAddr.sin_addr.s_addr);
	//或者是  serAddr.sin_addr.s_addr=inet_addr(serIP);
	serAddr.sin_addr.s_addr = inet_addr(serIP);

	printf("目标服务器地址：%s: %d\n", inet_ntoa(serAddr.sin_addr), ntohs(serAddr.sin_port));

	if (connect(sock, (struct sockaddr *) &serAddr, sizeof(serAddr)) < 0) {
		printf("connect Error!!\n");
		return -1;
	}
	*connSock = sock;
	return 0;
}


CNode* CConnman::ConnectNode(const char *address)
{
	std::string ipaddress = "192.168.10.210";
	unsigned short port= 8888;
	int sock = 0;
	int ret = ConnectRemoteSocket(ipaddress.c_str(),port,&sock);
	if (ret)
	{
		printf("ConnectRemoteSocket fail\n");
		return nullptr;
	}
	CNode *pnode = new CNode(sock, ipaddress);
	return pnode;
}

void CConnman::OpenNetworkConnection(const char *destAddr)
{
	std::cout <<"=====OpenNetworkConnection======="<< std::endl;
	//1：查找节点是否存在
	//if (FindNode(std::string(destAddr)))//否则找目标节点看是否存在，如果存在则返回
	//	return;
	//2：连接节点，返回一个新的节点
	CNode* pnode = ConnectNode(destAddr);

	//3: 连接成功的节点初始化，添加节点成功
	//这里构造节点
	if (pnode == nullptr)
	{
		std::cout << "connectNode fail" << std::endl;
		return;
	}
	m_msgproc->InitializeNode(pnode);//即所谓的创建一个新的节点
	{
		LOCK(cs_vNodes);
		vNodes.push_back(pnode);
	}
	m_msgproc->SendMessages(pnode);
}
//获取添加节点的信息
std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo()
{
	std::vector<AddedNodeInfo> ret;
	return ret;
}

//消息处理接口
void CConnman::ThreadMessageHandler()
{
	while (!flagInterruptMsgProc)
	{
		std::vector<CNode*> vNodesCopy;
		{
			LOCK(cs_vNodes);
			vNodesCopy = vNodes;
			for (CNode* pnode : vNodesCopy) {
				pnode->AddRef();//增加节点的引用
			}
		}
		bool fMoreWork = false;

		for (CNode* pnode : vNodesCopy)
		{
			if (pnode->fDisconnect)
				continue;

			// Receive messages  虚接口，接收处理消息
			bool fMoreNodeWork = m_msgproc->ProcessMessages(pnode);

			// Send messages     虚接口，发送消息
			{
				LOCK(pnode->cs_sendProcessing);//加锁
				std::unique_lock<std::mutex> lock(pnode->mutexSendMsg);
				m_msgproc->SendMessages(pnode);//发送消息
			}

			if (flagInterruptMsgProc)
				return;
		 }
		{
			LOCK(cs_vNodes);
			for (CNode* pnode : vNodesCopy)
				pnode->Release();
		}
	}

}

void CConnman::ThreadOpenConnections(const std::vector<std::string> connect)
{
	std::string conn = "192.168.10.210";
	std::vector<std::string> test_connect;
	test_connect.push_back(conn);
	for (const std::string& strAddr : test_connect)//依次建立连接，connect为从外部传入的节点集合
	{
		//CAddress addr(CService(), NODE_NONE);
		OpenNetworkConnection(strAddr.c_str());//打开每一个连接
	}
}

//接受连接
void CConnman::AcceptConnection(const ListenSocket& hListenSocket) 
{
	std::cout << "====AcceptConnection=====" << std::endl;
	struct sockaddr_storage sockaddr;
	socklen_t len = sizeof(sockaddr);
	SOCKET hSocket = accept(hListenSocket.socket, (struct sockaddr*)&sockaddr, &len);
	CAddress addr;
	int nInbound = 0;
	int nMaxInbound = nMaxConnections - (nMaxOutbound + nMaxFeeler);

	bool whitelisted = hListenSocket.whitelisted;
	int nsend=send(hSocket, "hello,world", strlen("hello,world"), 0);
	printf("send %d size",nsend);
	if (hSocket != INVALID_SOCKET) {
		if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr)) {
			LogPrintf("Warning: Unknown socket family\n");
		}
	}
	
	if (hSocket == INVALID_SOCKET)
	{
		int nErr = WSAGetLastError();
		if (nErr != WSAEWOULDBLOCK)
			LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
		return;
	}

	if (!IsSelectableSocket(hSocket))
	{
		LogPrintf("connection from %s dropped: non-selectable socket\n", addr.ToString());
		CloseSocket(hSocket);
		return;
	}

	// According to the internet TCP_NODELAY is not carried into accepted sockets
	// on all platforms.  Set it again here just to be sure.
	SetSocketNoDelay(hSocket);

	//NodeId id = GetNewNodeId();
	NodeId id=0;
	CNode* pnode = new CNode(id,hSocket,addr);//这边需要用参数初始化，
	pnode->AddRef();
	pnode->fWhitelisted = whitelisted;

	m_msgproc->InitializeNode(pnode);//初始化一个节点

	LogPrint(BCLog::NET, "connection from %s accepted\n", addr.ToString());

	{
		LOCK(cs_vNodes);
		vNodes.push_back(pnode);
	}
	
}

int ReadHeader(int socket)
{
	
	char buffer[20] = { 0 };
	int nBytes = recv(socket, buffer, 20, 0);
	printf("收到头部字节=%d\n", nBytes);
	printf("%c,%c,%c,%c\n",buffer[0],buffer[1],buffer[2],buffer[3]);
	if ((buffer[0] != '@') || (buffer[1] != '#') || (buffer[2] != '$') || (buffer[1] != '%'))
		return 0;
	printf("收到命令：\n");
	for(int k=4;k<16;k++)
	{
		printf("%c",buffer[k]);
	}
	
	printf("\n");
	//printf("%c%c%c%c%c%c%c%c%c%c%c%c", buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]);
	unsigned int msg_len = (buffer[16] << 24) | (buffer[17] << 16) | (buffer[18] << 8) | buffer[19];
	printf("消息长度msg_len=%d\n",msg_len);
	return msg_len;
	/*
	printf("===================");
	int i = 0;
	for (i = 0; i < 20; i++)
	{
		printf("%02x ",buffer[i]);
	}
	printf("\n");
	*/
}
void ReadBody(int socket, int msg_len)
{
	char *buf = (char*)malloc(msg_len + 1);
	int nread = recv(socket,buf,msg_len, 0);
	printf("收到尾部字节=%d,msg=%s\n",nread,buf);
}



void CConnman::ThreadSocketHandler()
{
	//断开没有用的节点
	{
		LOCK(cs_vNodes);
		// Disconnect unused nodes
		std::vector<CNode*> vNodesCopy = vNodes;
		for (CNode* pnode : vNodesCopy)
		{
			if (pnode->fDisconnect)
			{
				// remove from vNodes 从总的节点里面给移走
				vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

				// release outbound grant (if any)
			//	pnode->grantOutbound.Release();

				// close socket and cleanup  关闭socket
				pnode->CloseSocketDisconnect();

				// hold in disconnected pool until all refs are released
				pnode->Release();//释放引用
				vNodesDisconnected.push_back(pnode);
			}
		}
	}
	LogPrint(BCLog::NET, "disconnect node count= %d\n", vNodesDisconnected.size());
	std::cout <<"断开的节点个数=" << vNodesDisconnected.size() << std::endl;
	//移除没有用的节点
	{
		// Delete disconnected nodes
		std::list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
		for (CNode* pnode : vNodesDisconnectedCopy)
		{
			// wait until threads are done using it
			if (pnode->GetRefCount() <= 0) {
				bool fDelete = false;
				{
					TRY_LOCK(pnode->cs_inventory, lockInv);
					if (lockInv) {
						TRY_LOCK(pnode->cs_vSend, lockSend);
						if (lockSend) {
							fDelete = true;
						}
					}
				}
				if (fDelete)
				{
					//从断开节点的集合中移走这个节点
					vNodesDisconnected.remove(pnode);
					DeleteNode(pnode);
				}
			}
		}
	}


	SOCKET sListen;
	if (InitAndListern(sListen, 8888) == 0)
		return;
	printf("Server wait for client connect...\n");
	fd_set fdSocket;
	FD_ZERO(&fdSocket);
	FD_SET(sListen, &fdSocket);//将sListen添加进该集合  
	while (true)
	{
		fd_set fdRead = fdSocket;
		int nRet = select(NULL, &fdRead, NULL, NULL, NULL);//  

		if (nRet <= 0)
			break;
		for (int i = 0; i < (int)fdSocket.fd_count; ++i)
		{
			if (FD_ISSET(fdSocket.fd_array[i], &fdRead))
			{
				if (fdSocket.fd_array[i] == sListen)
				{
					sockaddr_in addrRemote;
					int nAddrLen = sizeof(addrRemote);
					SOCKET sock = ::accept(sListen, (sockaddr*)&addrRemote, &nAddrLen);
					FD_SET(sock, &fdSocket);
					printf("Client %s connected\n", inet_ntoa(addrRemote.sin_addr));
					char *ip = inet_ntoa(addrRemote.sin_addr);
					std::string ipaddress(ip);
					CNode *pnode = new CNode(sock,ipaddress);//新建一个node，然后添加一个节点
					AddNode(pnode);	
				}
				else
				{
					std::vector<CNode*> vNodesCopy;
					{
						LOCK(cs_vNodes);
						vNodesCopy = vNodes;
						for (CNode* pnode : vNodesCopy)
							pnode->AddRef();//增加引用
					}
					for (CNode* pnode : vNodesCopy)
					{
						if (pnode == nullptr)
						{
							std::cout <<"pnode is null"<< std::endl;
							continue;
						}
						char buffer[100] = { 0 };
						memset(buffer, 0, 1024);
						int nBytes = recv(fdSocket.fd_array[i], buffer, 100, 0);
						
						if (nBytes > 0)
						{
							printf("Received Client Msg:%s\n",buffer);
							char *command = "GETBLOCK";
							if (memcmp(command, buffer+4, 8) == 0)
							{
								printf("receive client get block request\n");
								char sendbuf[100];
								strncpy(sendbuf, "BLOCK_DATA", 10);
								strcpy(sendbuf + 10, "This is block message");
								int nsend = send(fdSocket.fd_array[i], sendbuf, 100, 0);
								printf("nsend=%d\n", nsend);
							}
						}
						else
						{
							closesocket(fdSocket.fd_array[i]);
							DeleteNode(pnode);
							FD_CLR(fdSocket.fd_array[i], &fdSocket);
						}
					}
				}
				
			 }
		}
	}
}

//根据IP查找节点
CNode* CConnman::FindNode(const CNetAddr& ip)
{
	LOCK(cs_vNodes);
	for (CNode* pnode : vNodes) {
		if (static_cast<CNetAddr>(pnode->addr) == ip) {
			return pnode;
		}
	}
	return nullptr;
}
//根据socket，查找节点
CNode* CConnman::FindNode(SOCKET socket)
{
	LOCK(cs_vNodes);
	for (CNode* pnode : vNodes) {
		if (pnode->hSocket==socket) {
			return pnode;
		}
	}
	return nullptr;
}
//根据地址名找节点
CNode* CConnman::FindNode(const std::string& addrName)
{
	LOCK(cs_vNodes);
	for (CNode* pnode : vNodes) {
		if (pnode->GetAddrName() == addrName) {
			return pnode;
		}
	}
	return nullptr;
}
//根据地质类查找节点
CNode* CConnman::FindNode(const CService& addr)
{
	LOCK(cs_vNodes);
	for (CNode* pnode : vNodes) {
		if (static_cast<CService>(pnode->addr) == addr) {
			return pnode;
		}
	}
	return nullptr;
}
//添加节点
void CConnman::AddNode(CNode* pnode)
{
	LOCK(cs_vNodes);
	m_msgproc->InitializeNode(pnode);//给外部的接口
	vNodes.push_back(pnode);
	std::cout << "总的节点个数=" << vNodes.size()<<std::endl;
	
}
//移除节点
void CConnman::DeleteNode(CNode* pnode)
{
	m_msgproc->FinalizeNode(pnode);
	delete pnode;
}
