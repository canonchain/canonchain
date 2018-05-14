#pragma once

#include <czr/node/common.hpp>
#include <czr/node/node.hpp>
#include <czr/ledger.hpp>
#include <czr/blockstore.hpp>


namespace czr
{
	enum compose_result_codes
	{
		ok = 1,
		insufficient_balance,
		witness_list_not_found,
	};

	class compose_result
	{
	public:
		compose_result(czr::compose_result_codes const & code_a, std::shared_ptr<czr::block> block_a);
		czr::compose_result_codes code;
		std::shared_ptr<czr::block> block;
	};

	class compose_parents_result
	{
	public:
		compose_parents_result(czr::compose_result_codes const & code_a, std::vector<czr::account> const & parents_a);
		czr::compose_result_codes code;
		std::vector<czr::account> parents;
	};

	class composer
	{
	public:
		composer(czr::node & node_a);
		~composer();
		czr::compose_result compose(MDB_txn * transaction_a, czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> const & data_a, czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t const & work_a);
		czr::compose_parents_result compose_parents(MDB_txn * transaction_a, czr::witness_list_info my_wl_info);
		czr::node & node;
		czr::ledger & ledger;

	};
}