#pragma once

#include <czr/node/common.hpp>
#include <czr/node/node.hpp>
#include <czr/ledger.hpp>
#include <czr/blockstore.hpp>


namespace czr
{
	enum class compose_result_codes
	{
		ok,
		insufficient_balance,
		data_size_too_large,
		error
	};

	class compose_result
	{
	public:
		compose_result(czr::compose_result_codes const & code_a, std::shared_ptr<czr::block> block_a);
		czr::compose_result_codes code;
		std::shared_ptr<czr::block> block;
	};

	class composer
	{
	public:
		composer(czr::node & node_a);
		~composer();
		czr::compose_result compose(MDB_txn * transaction_a, czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> const & data_a, czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t const & work_a);
		std::vector<czr::block_hash> pick_deep_parents(MDB_txn * transaction_a, czr::witness_list_info const & my_wl_info, boost::optional<uint64_t> const & max_wl);
		std::vector<czr::block_hash> check_wl_not_retreating_and_look_lower(MDB_txn * transaction_a, czr::witness_list_info const & my_wl_info, std::vector<czr::block_hash> const & parents);
		czr::node & node;
		czr::ledger & ledger;

	};
}