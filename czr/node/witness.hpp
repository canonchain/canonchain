#pragma once

#include "czr/node/node.hpp"

namespace czr
{
	class witness:std::enable_shared_from_this<czr::witness>
	{
	public:
		witness(czr::error_message & error_msg, czr::node & node_a, std::string const & wallet_text, std::string const & account_text);
		void start();
		void ongoing_send();

		czr::node & node;
		std::shared_ptr<czr::wallet> wallet;
		czr::account account;
	};
}