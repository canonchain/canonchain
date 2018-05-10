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
		consensus(czr::node &, czr::ledger &, MDB_txn *, std::function<void(std::shared_ptr<czr::block>)>);
		~consensus();
		czr::process_return process(czr::publish const & message);

		czr::node & node;
		czr::ledger & ledger;
		MDB_txn * transaction;
		std::function<void(std::shared_ptr<czr::block>)> block_stable_observer;
	private:
		czr::process_return validate(czr::publish const & message);
		void save_block(czr::block const &, bool const &);
		void update_main_chain(czr::block const &);
		void check_mc_stable_block();
		void update_parent_mc_index(czr::block_hash const &, uint64_t const &, std::shared_ptr<std::unordered_set<czr::block_hash>>);
		void update_stable_block(czr::block_hash const &, uint64_t const &, std::shared_ptr<std::set<czr::block_hash>>);
		bool check_stable_from_view_of_parents_and_previous(czr::block_hash const & check_hash, czr::block_hash const & later_hash);
		void advance_mc_stable_block(czr::block_hash const & mc_stable_hash, uint64_t const & mci);
		void rollback(czr::block_hash const &);
		void change_successor(czr::block_hash const &);
		void find_unstable_child_blocks(czr::block_hash const & stable_hash, czr::block_hash & mc_child_hash, std::shared_ptr<std::vector<czr::block_hash>> branch_child_hashs);
		uint64_t find_mc_min_wl(czr::block_hash const & best_block_hash, czr::witness_list_info const & witness_list);
		czr::summary_hash gen_summary_hash(czr::block_hash const & block_hash, std::vector<czr::summary_hash> const & parent_hashs, std::set<czr::summary_hash> const & skip_list, bool const & is_fork, bool const & is_error, bool const & is_fail, czr::account_state_hash const & from_state_hash, czr::account_state_hash const & to_state_hash);
		std::vector<uint64_t> cal_skip_list_mcis(uint64_t const &);
		czr::block_hash determine_best_parent(std::vector<czr::block_hash> const & pblock_hashs, czr::witness_list_info const & wl_info);
		bool check_witness_list_mutations_along_mc(czr::block_hash const & best_parent, czr::block const & block);
		uint64_t determine_witness_level(czr::block_hash const & best_parent_hash, czr::witness_list_info const & wl_info);
	};
}