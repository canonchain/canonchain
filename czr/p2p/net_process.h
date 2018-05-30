#pragma once
#include "net.h"

class PeerLogicValidation final : public NetEventsInterface 
{
private:
	CConnman* const connman;//保存连接管理类的指针

public:
	explicit PeerLogicValidation(CConnman* conn):connman(conn){};

	void InitializeNode(CNode* pnode) override;

	void FinalizeNode(CNode* pnode) override;

	bool ProcessMessages(CNode* pfrom) override;

	bool SendMessages(CNode* pto) override;

};
