#pragma once

#include <czr/node/common.hpp>
#include <czr/node/node.hpp>
#include <czr/ledger.hpp>
#include <czr/blockstore.hpp>

#include <set>
#include <unordered_set>


namespace czr
{
	class node;

	class validation
	{
	public:
		validation(czr::node & node_a);
		~validation();

		czr::validate_result validate(MDB_txn * transaction_a, czr::publish const & message);

		czr::node & node;
		czr::ledger & ledger;
	};
}