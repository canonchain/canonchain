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
	virtual bool ProcessMessages(CNode* pnode) = 0;//������Ϣ
	virtual bool SendMessages(CNode* pnode) = 0;//������Ϣ
	virtual void InitializeNode(CNode* pnode) = 0;//��ʼ���ڵ�
	virtual void FinalizeNode(CNode* pnode) = 0;//���ٽڵ�

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

	//��������
	CNode* AddRef()
	{
		nRefCount++;
		return this;
	}
	//��������
	void Release()
	{
		nRefCount--;
	}
	int GetRefCount() const
	{

		return nRefCount;
	}
	//��ȡ��ַ��
	std::string GetAddrName() const 
	{
		LOCK(cs_addrName);
		return addrName;
	}
	std::string ip_address;//������192.168.10.210��ַ
	
public:
	std::atomic<int> nRefCount;//���ø���
	bool fWhitelisted;//�Ƿ��ڰ�������
	bool fDisconnect;//�Ƿ�Ͽ���־
	bool flagInterruptMsgProc;//��Ϣ�����Ƿ��жϱ�־

	std::atomic_bool fPauseRecv;//��ͣ����
	std::atomic_bool fPauseSend;//��ͣ����


	CCriticalSection cs_vSend;
	CCriticalSection cs_hSocket;
	CCriticalSection cs_vRecv;
	CCriticalSection cs_inventory;

	CCriticalSection cs_sendProcessing;//���͵�ʱ����
	std::deque<std::vector<unsigned char>> vSendMsg;//������Ϣ

	mutable CCriticalSection cs_addrName;
	std::string addrName;

	NodeId id;//�ڵ�id
	SOCKET hSocket;//�ڵ�socket
	std::mutex mutexSendMsg;//������Ϣʱ����

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
	
	void ThreadSocketHandler();//����socket

	void ThreadMessageHandler();//������Ϣ

	//void ThreadDNSAddressSeed();
	//void ThreadOpenAddedConnections();//���Ѿ���ӽڵ������
	//void ThreadOpenConnections();
	
	void ThreadOpenConnections(const std::vector<std::string> connect);
	
	std::vector<AddedNodeInfo> GetAddedNodeInfo();
	void OpenNetworkConnection(const char *destAddr);
	

	//��������
	int nMaxConnections;
	int nMaxOutbound;
	//����
	int nMaxAddnode;
	int nMaxFeeler;
private:
	struct ListenSocket {
		SOCKET socket;
		bool whitelisted;

		ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
	};
	std::vector<ListenSocket> vhListenSocket;//����socket����

	/** flag for waking the message processor. */
	bool fMsgProcWake;//�Ƿ�����Ϣ����ı�־

	std::condition_variable condMsgProc;//��Ϣ�������������
	std::mutex mutexMsgProc;//������
	std::atomic<bool> flagInterruptMsgProc;//�жϱ�־

	std::mutex mutexAddNodes;//��ӽڵ��ʱ�����
	std::vector<CNode*> vNodes; //�ܵĽڵ�
	std::list<CNode*> vNodesDisconnected;//�Ͽ��Ľڵ�
	NetEventsInterface* m_msgproc;

	std::unique_ptr<CSemaphore> semAddnode;//��ӽڵ���ź���
	CThreadInterrupt interruptNet;//�����߳��жϵ�

	CCriticalSection cs_vAddedNodes;//��ӽڵ�ʱ����
	std::vector<std::string> vAddedNodes GUARDED_BY(cs_vAddedNodes);//���ⲿ��ӵĽڵ�

	mutable CCriticalSection cs_vNodes;//���ҽڵ�ʱ����

	std::thread threadSocketHandler;//socket�շ��������������
	std::thread threadMessageHandler;//��Ϣ�����߳�
	std::thread threadOpenConnections;//�������߳�

public:

	//��ӽڵ�
	void AddNode(CNode* pnode);

	//ɾ���ڵ�
	void DeleteNode(CNode* pnode);

	//���ҽڵ�
	CNode* FindNode(const CNetAddr& ip);
	CNode* FindNode(SOCKET socket);
	CNode* FindNode(const std::string& addrName);
	CNode* FindNode(const CService& addr);

	//�������ӽڵ�
	CNode* ConnectNode(const char *destAddr);
	//��������
	void AcceptConnection(const ListenSocket& hListenSocket);
	//�ײ�����Ӻ���
	int ConnectRemoteSocket(const char *serIP, unsigned short serPort,int *socket);
};

#endif