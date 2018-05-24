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

	class chain
	{
	public:
		chain(czr::node & node_a, std::function<void(std::shared_ptr<czr::block>)> block_stable_observer_a);
		~chain();

		void save_block(MDB_txn * transaction_a, czr::block const & block_a);
		void advance_mc_stable_block(MDB_txn * transaction_a, czr::block_hash const & mc_stable_hash, uint64_t const & mci);

		czr::node & node;
		czr::ledger & ledger;
		std::function<void(std::shared_ptr<czr::block>)> block_stable_observer;

	private:
		void update_main_chain(MDB_txn * transaction_a, czr::block const &);
		void check_mc_stable_block(MDB_txn * transaction_a);
		void update_parent_mci(MDB_txn * transaction_a, czr::block_hash const &, uint64_t const &, std::shared_ptr<std::unordered_set<czr::block_hash>>);
		void search_stable_block(MDB_txn * transaction_a, czr::block_hash const &, uint64_t const &, std::shared_ptr<std::set<czr::block_hash>>);
		void rollback(MDB_txn * transaction_a, czr::block_hash const &);
		void change_successor(MDB_txn * transaction_a, czr::block_hash const &);
		std::vector<uint64_t> cal_skip_list_mcis(uint64_t const &);
	};
}