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
	std::cout<<"添加节点"<<std::endl;
	std::cout<< "地址="<<pnode->ip_address<<" socket="<<pnode->hSocket<<std::endl;
}
//销毁节点
void PeerLogicValidation::FinalizeNode(CNode *pnode)
{
	std::cout << "销毁节点" << std::endl;
	std::cout << "地址=" << pnode->ip_address << " socket=" << pnode->hSocket << std::endl;

}
//处理消息
bool PeerLogicValidation::ProcessMessages(CNode* pfrom)
{
	std::cout << "接收消息，处理..." << std::endl;
	return true;
}
//发送消息
bool PeerLogicValidation::SendMessages(CNode* pto)
{
	std::cout << "发送消息" << std::endl;
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