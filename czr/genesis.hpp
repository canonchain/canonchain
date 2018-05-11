#pragma once

#include <czr/common.hpp>
#include <czr/blockstore.hpp>
#include <czr/lib/blocks.hpp>
#include <czr/node/utility.hpp>
#include <set>

namespace czr
{
	class genesis
	{
	public:
		static void try_initialize(MDB_txn * transaction_a, czr::block_store & store_a);
		static czr::block_hash block_hash;
	};
}
