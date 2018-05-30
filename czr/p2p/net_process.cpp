#include "net_process.h"
#include "net.h"
#include <iostream>

void PeerLogicValidation::InitializeNode(CNode *pnode) 
{
	/*
	CAddress addr = pnode->addr;
	std::string addrName = pnode->GetAddrName();
	NodeId nodeid = pnode->GetId();
	{
		LOCK(cs_main);
		mapNodeState.emplace_hint(mapNodeState.end(), std::piecewise_construct, std::forward_as_tuple(nodeid), std::forward_as_tuple(addr, std::move(addrName)));
	}
	if (!pnode->fInbound)
		PushNodeVersion(pnode, connman, GetTime());
	*/
	std::cout<<"��ӽڵ�"<<std::endl;
	std::cout<< "��ַ="<<pnode->ip_address<<" socket="<<pnode->hSocket<<std::endl;
}
//���ٽڵ�
void PeerLogicValidation::FinalizeNode(CNode *pnode)
{
	std::cout << "���ٽڵ�" << std::endl;
	std::cout << "��ַ=" << pnode->ip_address << " socket=" << pnode->hSocket << std::endl;

}
//������Ϣ
bool PeerLogicValidation::ProcessMessages(CNode* pfrom)
{
	std::cout << "������Ϣ������..." << std::endl;
	return true;
}
//������Ϣ
bool PeerLogicValidation::SendMessages(CNode* pto)
{
	std::cout << "������Ϣ" << std::endl;
	char *sendstr = "hello,I am the block 100";
	int ret=send(pto->hSocket,sendstr,strlen(sendstr)+1, 0);
	if (ret >0)
	{
		printf("send success\n");
	}
	else
	{
		printf("send fail ret=%d\n",ret);

	}
	return true;
}