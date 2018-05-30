#pragma once
#include "net.h"

class PeerLogicValidation final : public NetEventsInterface 
{
private:
	CConnman* const connman;//�������ӹ������ָ��

public:
	explicit PeerLogicValidation(CConnman* conn):connman(conn){};

	void InitializeNode(CNode* pnode) override;

	void FinalizeNode(CNode* pnode) override;

	bool ProcessMessages(CNode* pfrom) override;

	bool SendMessages(CNode* pto) override;

};
