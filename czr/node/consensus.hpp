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

	class consensus
	{
	public:
		consensus(czr::node & node_a, MDB_txn * transaction, std::function<void(std::shared_ptr<czr::block>)> block_stable_observer_a);
		~consensus();
		czr::process_return process(czr::publish const & message);

		czr::node & node;
		czr::ledger & ledger;
		MDB_txn * transaction;
		std::function<void(std::shared_ptr<czr::block>)> block_stable_observer;
	private:
		czr::process_return validate(czr::publish const & message);
		void save_block(czr::block const & block_a);
		void update_main_chain(czr::block const &);
		void check_mc_stable_block();
		void update_parent_mc_index(czr::block_hash const &, uint64_t const &, std::shared_ptr<std::unordered_set<czr::block_hash>>);
		void update_stable_block(czr::block_hash const &, uint64_t const &, std::shared_ptr<std::set<czr::block_hash>>);
		void advance_mc_stable_block(czr::block_hash const & mc_stable_hash, uint64_t const & mci);
		void rollback(czr::block_hash const &);
		void change_successor(czr::block_hash const &);
		czr::summary_hash gen_summary_hash(czr::block_hash const & block_hash, std::vector<czr::summary_hash> const & parent_hashs, std::set<czr::summary_hash> const & skip_list, bool const & is_fork, bool const & is_error, bool const & is_fail, czr::account_state_hash const & from_state_hash, czr::account_state_hash const & to_state_hash);
		std::vector<uint64_t> cal_skip_list_mcis(uint64_t const &);
	};
}