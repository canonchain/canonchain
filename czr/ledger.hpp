#pragma once

#include <czr/common.hpp>

namespace czr
{
	class block_store;

	class shared_ptr_block_hash
	{
	public:
		size_t operator() (std::shared_ptr<czr::block> const &) const;
		bool operator() (std::shared_ptr<czr::block> const &, std::shared_ptr<czr::block> const &) const;
	};

	class ledger
	{
	public:
		ledger(czr::block_store &);
		czr::account block_account(MDB_txn *, czr::block_hash const &);
		czr::uint128_t account_balance(MDB_txn *, czr::account const &);
		std::unique_ptr<czr::block> successor(MDB_txn *, czr::block_hash const &);
		czr::witness_list_info block_witness_list(MDB_txn * transaction_a, czr::block const & block_a);
		czr::block_hash latest(MDB_txn *, czr::account const &);
		czr::block_hash latest_root(MDB_txn *, czr::account const &);
		bool block_exists(czr::block_hash const &);
		void change_account_latest(MDB_txn *, czr::account const &, czr::block_hash const &, uint64_t const &);
		void try_set_account_good_stable_mci(MDB_txn * transaction_a, czr::account const & account_a, uint64_t good_stable_mci);
		void dump_account_chain(czr::account const &);

		czr::block_hash determine_best_parent(MDB_txn * transaction_a, std::vector<czr::block_hash> const & pblock_hashs, czr::witness_list_info const & wl_info);
		uint64_t determine_witness_level(MDB_txn * transaction_a, czr::block_hash const & best_parent_hash, czr::witness_list_info const & wl_info);
		bool check_witness_list_mutations_along_mc(MDB_txn * transaction_a, czr::block_hash const & best_parent_hash, czr::block const & block_a);
		bool check_witness_list_mutations_along_mc(MDB_txn * transaction_a, czr::block_hash const & best_parent_hash, czr::witness_list_info const & wl_info, czr::block_hash const & witness_list_block_hash, czr::block_hash const & last_summary_block_hash);
		void find_unstable_child_blocks(MDB_txn * transaction_a, czr::block_hash const & stable_hash, czr::block_hash & mc_child_hash, std::shared_ptr<std::list<czr::block_hash>> branch_child_hashs);
		uint64_t find_mc_min_wl(MDB_txn * transaction_a, czr::block_hash const & best_block_hash, czr::witness_list_info const & witness_list);
		bool check_stable_from_later_blocks(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs);
		czr::block_hash find_witness_list_block(MDB_txn * transaction_a, czr::witness_list_info const & wl_info, uint64_t const & last_stable_mci);
		void witness_list_put(MDB_txn* transaction_a,czr::witness_list_info const & wl_info);
		void witness_list_get(MDB_txn* transaction_a, czr::witness_list_info & wl_info);
		static czr::uint128_t const unit;
		czr::block_store & store;
	};
};
