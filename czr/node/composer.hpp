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
		czr::compose_result compose(MDB_txn * transaction_a, czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> const & data_a, czr::raw_key const & prv_a, czr::public_key const & pub_a);
		void pick_parents_and_last_summary_and_wl_block(czr::error_message & err_msg, MDB_txn * transaction_a, czr::block_hash previous, czr::witness_list_info const & my_wl_info, std::vector<czr::block_hash>& parents, czr::block_hash & last_summary_block, czr::summary_hash & last_summary, uint64_t & last_stable_mci, czr::block_hash & witness_list_block);
		std::vector<czr::block_hash> pick_deep_parents(czr::error_message & err_msg, MDB_txn * transaction_a, czr::block_hash const & previous, czr::witness_list_info const & my_wl_info, boost::optional<uint64_t> const & max_wl, bool const & is_previous_compatible_and_retreat);
		std::vector<czr::block_hash> check_witnessed_level_not_retreating_and_look_lower(czr::error_message & err_msg, MDB_txn * transaction_a, czr::block_hash const & previous, czr::witness_list_info const & my_wl_info, std::vector<czr::block_hash> const & parents, bool const & is_previous_compatible_and_retreat);
		void adjust_parents_to_not_retreat_witnessed_level(czr::error_message & err_msg, MDB_txn * transaction_a, czr::witness_list_info const & my_wl_info, czr::block_hash const & previous, std::vector<czr::block_hash>& parents, czr::block_hash & best_parent);
		void replace_excluded_parent(MDB_txn * transaction_a, czr::block_hash const & excluded_hash, std::vector<czr::block_hash>& parents, std::shared_ptr<std::unordered_set<block_hash>> all_excluded_hashs);
		void adjust_last_summary_and_parents(czr::error_message & err_msg, MDB_txn * transaction_a, czr::block_hash const & previous, czr::witness_list_info const & my_wl_info, czr::block_hash & last_summary_block_hash, std::vector<czr::block_hash>& parents, bool const & is_previous_compatible_and_retreat);
		std::vector<czr::block_hash> parents_and_previous(std::vector<czr::block_hash> const & parents, czr::block_hash const & previous);
		
		czr::node & node;
		czr::ledger & ledger;
	};
}