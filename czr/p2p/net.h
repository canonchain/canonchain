#pragma once
#ifndef __NET__H
#define __NET__H
#include <string>
#include <vector>
#include <stdint.h>
#include <atomic>
#include <thread>
#include <list>
#include <deque>
#include <mutex>
#include "compat.h"
#include "netaddress.h"
#include "threadinterrupt.h"
#include "sync.h"
#include "protocol.h"


class CScheduler;
class CNode;
typedef int64_t NodeId;

struct AddedNodeInfo
{
	std::string strAddedNode;
	CService resolvedAddress;
	bool fConnected;
	bool fInbound;
};

class CNodeStats;
class CClientUIInterface;

struct CSerializedNetMsg
{
	CSerializedNetMsg() = default;
	CSerializedNetMsg(CSerializedNetMsg&&) = default;
	CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;
	// No copying, only moves.
	CSerializedNetMsg(const CSerializedNetMsg& msg) = delete;
	CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;

	std::vector<unsigned char> data;
	std::string command;
};
class NetEventsInterface
{
public:
	virtual bool ProcessMessages(CNode* pnode) = 0;//处理消息
	virtual bool SendMessages(CNode* pnode) = 0;//发送消息
	virtual void InitializeNode(CNode* pnode) = 0;//初始化节点
	virtual void FinalizeNode(CNode* pnode) = 0;//销毁节点

protected:
	~NetEventsInterface() = default;
};

class CNode
{
public:
	CNode() {}
	CNode(SOCKET hSocketIn, std::string ip) :hSocket(hSocketIn), ip_address(ip) {}
	CNode(NodeId idIn, SOCKET hSocketIn, const CAddress &addrIn):id(idIn),hSocket(hSocketIn),addr(addrIn){}
	~CNode(){};
	CNode(const CNode&) = delete;
	CNode& operator=(const CNode&) = delete;

	//增加引用
	CNode* AddRef()
	{
		nRefCount++;
		return this;
	}
	//减少引用
	void Release()
	{
		nRefCount--;
	}
	int GetRefCount() const
	{

		return nRefCount;
	}
	//获取地址名
	std::string GetAddrName() const 
	{
		LOCK(cs_addrName);
		return addrName;
	}
	std::string ip_address;//类似于192.168.10.210地址
	
public:
	std::atomic<int> nRefCount;//引用个数
	bool fWhitelisted;//是否在白名单中
	bool fDisconnect;//是否断开标志
	bool flagInterruptMsgProc;//消息发送是否中断标志

	std::atomic_bool fPauseRecv;//暂停接收
	std::atomic_bool fPauseSend;//暂停发送


	CCriticalSection cs_vSend;
	CCriticalSection cs_hSocket;
	CCriticalSection cs_vRecv;
	CCriticalSection cs_inventory;

	CCriticalSection cs_sendProcessing;//发送的时候锁
	std::deque<std::vector<unsigned char>> vSendMsg;//发送消息

	mutable CCriticalSection cs_addrName;
	std::string addrName;

	NodeId id;//节点id
	SOCKET hSocket;//节点socket
	std::mutex mutexSendMsg;//发送消息时加锁

	const CAddress addr;
	const CAddress addrBind;
	bool fInbound;
	void CloseSocketDisconnect();
	bool ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool& complete);


};


/////////////////////////////////////////////////////////////////////////////////////////////////////////


class CConnman
{
public:
	CConnman(){}
	~CConnman(){}
	struct Options
	{
		/*
		ServiceFlags nLocalServices = NODE_NONE;
		int nMaxConnections = 0;
		int nMaxOutbound = 0;
		int nMaxAddnode = 0;
		int nMaxFeeler = 0;
		int nBestHeight = 0;
		CClientUIInterface* uiInterface = nullptr;
		NetEventsInterface* m_msgproc = nullptr;
		unsigned int nSendBufferMaxSize = 0;
		unsigned int nReceiveFloodSize = 0;
		uint64_t nMaxOutboundTimeframe = 0;
		uint64_t nMaxOutboundLimit = 0;
		std::vector<std::string> vSeedNodes;
		std::vector<CSubNet> vWhitelistedRange;
		std::vector<CService> vBinds, vWhiteBinds;
		bool m_use_addrman_outgoing = true;
		*/
		std::vector<std::string> m_specified_outgoing;
		std::vector<std::string> m_added_nodes;
	};
	void Start();
	void Stop();
	void Wait();
	bool InitAndListern(SOCKET &sListen, uint16_t port);
	
	void ThreadSocketHandler();//处理socket

	void ThreadMessageHandler();//处理消息

	//void ThreadDNSAddressSeed();
	//void ThreadOpenAddedConnections();//打开已经添加节点的连接
	//void ThreadOpenConnections();
	
	void ThreadOpenConnections(const std::vector<std::string> connect);
	
	std::vector<AddedNodeInfo> GetAddedNodeInfo();
	void OpenNetworkConnection(const char *destAddr);
	

	//最大的连接
	int nMaxConnections;
	int nMaxOutbound;
	//最大的
	int nMaxAddnode;
	int nMaxFeeler;
private:
	struct ListenSocket {
		SOCKET socket;
		bool whitelisted;

		ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
	};
	std::vector<ListenSocket> vhListenSocket;//监听socket集合

	/** flag for waking the message processor. */
	bool fMsgProcWake;//是否唤醒消息处理的标志

	std::condition_variable condMsgProc;//消息处理的条件变量
	std::mutex mutexMsgProc;//互斥锁
	std::atomic<bool> flagInterruptMsgProc;//中断标志

	std::mutex mutexAddNodes;//添加节点的时候的锁
	std::vector<CNode*> vNodes; //总的节点
	std::list<CNode*> vNodesDisconnected;//断开的节点
	NetEventsInterface* m_msgproc;

	std::unique_ptr<CSemaphore> semAddnode;//添加节点的信号量
	CThreadInterrupt interruptNet;//管理线程中断的

	CCriticalSection cs_vAddedNodes;//添加节点时的锁
	std::vector<std::string> vAddedNodes GUARDED_BY(cs_vAddedNodes);//从外部添加的节点

	mutable CCriticalSection cs_vNodes;//查找节点时的锁

	std::thread threadSocketHandler;//socket收发句柄，接受连接
	std::thread threadMessageHandler;//消息处理线程
	std::thread threadOpenConnections;//打开连接线程

public:

	//添加节点
	void AddNode(CNode* pnode);

	//删除节点
	void DeleteNode(CNode* pnode);

	//查找节点
	CNode* FindNode(const CNetAddr& ip);
	CNode* FindNode(SOCKET socket);
	CNode* FindNode(const std::string& addrName);
	CNode* FindNode(const CService& addr);

	//主动连接节点
	CNode* ConnectNode(const char *destAddr);
	//接收连接
	void AcceptConnection(const ListenSocket& hListenSocket);
	//底层的连接函数
	int ConnectRemoteSocket(const char *serIP, unsigned short serPort,int *socket);
};

#endif