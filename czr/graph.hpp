#pragma once

#include <czr/blockstore.hpp>
#include <czr/common.hpp>

namespace czr
{
	enum class graph_compare_result
	{
		non_related = 0,			//hash1 and hash2 are not related
		equal = 1,					//hash1 == hash2
		hash1_included_by_hash2,	//hash1 is included by hash2
		hash2_included_by_hash1,	//hash2 is included by hash1
	};

	class graph
	{
	public:
		graph(czr::block_store &);
		czr::graph_compare_result compare(MDB_txn * transaction_a, czr::block_hash hash1, czr::block_hash hash2);
		bool determine_if_included(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs);
		bool determine_if_included_or_equal(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs);

	private:
		bool go_up_check_included(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs);
		bool go_down_check_included(MDB_txn * transaction_a, czr::block_hash const & later_hash, std::vector<czr::block_hash> const & earlier_hashs);

		czr::block_store & store;
	};
};
