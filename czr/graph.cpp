#include <czr/graph.hpp>
#include <czr/genesis.hpp>

#include <unordered_set>


czr::graph::graph(czr::block_store & store_a):
	store(store_a)
{
}

czr::graph_compare_result czr::graph::compare(MDB_txn * transaction_a, czr::block_hash hash1, czr::block_hash hash2)
{
	if (hash1 == hash2)
		return graph_compare_result::equal;

	czr::block_state state1;
	bool state1_error(store.block_state_get(transaction_a, hash1, state1));
	assert(!state1_error);

	czr::block_state state2;
	bool state2_error(store.block_state_get(transaction_a, hash1, state2));
	assert(!state2_error);

	if (state1.level == state2.level)
		return graph_compare_result::non_related;
	if(state1.is_free && state2.is_free)
		return graph_compare_result::non_related;

	// genesis
	if (!state1.latest_included_mc_index)
		return graph_compare_result::hash1_included_by_hash2;
	if (!state2.latest_included_mc_index)
		return graph_compare_result::hash2_included_by_hash1;

	if (state2.main_chain_index && *state1.latest_included_mc_index >= *state2.main_chain_index)
		return graph_compare_result::hash2_included_by_hash1;
	if (state1.main_chain_index && *state2.latest_included_mc_index >= *state1.main_chain_index)
		return graph_compare_result::hash1_included_by_hash2;

	if ((state1.level <= state2.level
		&& *state1.latest_included_mc_index <= *state2.latest_included_mc_index
		&& (!state1.main_chain_index
			|| !state2.main_chain_index
			|| (*state1.main_chain_index <= *state2.main_chain_index)))
		||
		(state1.level >= state2.level
			&& *state1.latest_included_mc_index >= *state2.latest_included_mc_index
			&& (!state1.main_chain_index
				|| !state2.main_chain_index
				|| (*state1.main_chain_index >= *state2.main_chain_index))))
	{
	}
	else
		return graph_compare_result::non_related;

	czr::block_hash earlier_hash(state1.level < state2.level ? hash1 : hash2);
	czr::block_state earlier_state(state1.level < state2.level ? state1 : state2);
	czr::block_hash later_hash(state1.level < state2.level ? hash2 : hash1);
	czr::block_state later_state(state1.level < state2.level ? state2 : state1);
	czr::graph_compare_result result_if_found = state1.level < state2.level ? graph_compare_result::hash1_included_by_hash2 
																		: graph_compare_result::hash2_included_by_hash1;

	uint64_t earlier_delta((earlier_state.main_chain_index ? *earlier_state.main_chain_index : 0) - *earlier_state.latest_included_mc_index);
	uint64_t later_delta((later_state.main_chain_index ? *later_state.main_chain_index : 0) - *later_state.latest_included_mc_index);

	if (later_delta > earlier_delta)
	{
		std::vector<czr::block_hash> later_hashs;
		later_hashs.push_back(later_hash);

		if (go_up_check_included(transaction_a, earlier_hash, later_hashs))
			return result_if_found;
	}
	else
	{
		std::vector<czr::block_hash> earlier_hashs;
		earlier_hashs.push_back(earlier_hash);

		if (go_down_check_included(transaction_a, later_hash, earlier_hashs))
			return result_if_found;
	}

	return graph_compare_result::non_related;
}

bool czr::graph::determine_if_included(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs)
{
	if (earlier_hash == czr::genesis::block_hash)
		return true;
	czr::block_state earlier_state;
	bool earlier_state_error(store.block_state_get(transaction_a, earlier_hash, earlier_state));
	assert(!earlier_state_error);
	if (earlier_state.is_free)
		return false;

	uint64_t max_later_limci(0);
	uint64_t max_later_level(0);
	for (czr::block_hash const & later_hash : later_hashs)
	{
		czr::block_state later_state;
		bool later_state_error(store.block_state_get(transaction_a, later_hash, later_state));
		assert(!later_state_error);

		if (later_state.latest_included_mc_index
			&& *later_state.latest_included_mc_index > max_later_limci)
			max_later_limci = *later_state.latest_included_mc_index;

		if (later_state.level > max_later_level)
			max_later_level = later_state.level;
	}

	if (earlier_state.main_chain_index
		&& max_later_limci >= *earlier_state.main_chain_index)
		return true;

	if (max_later_level < earlier_state.level)
		return false;

	return go_up_check_included(transaction_a, earlier_hash, later_hashs);
}

bool czr::graph::determine_if_included_or_equal(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs)
{
	if (std::find(later_hashs.begin(), later_hashs.end(), earlier_hash) != later_hashs.end())
		return true;
	return determine_if_included(transaction_a, earlier_hash, later_hashs);
}

bool czr::graph::go_up_check_included(MDB_txn * transaction_a , czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const &  later_hashs)
{
	czr::block_state earlier_state;
	bool earlier_state_error(store.block_state_get(transaction_a, earlier_hash, earlier_state));
	assert(!earlier_state_error);

	std::unordered_set<czr::block_hash> searched_hashs;
	std::vector<czr::block_hash> search_hashs(later_hashs);
	while (search_hashs.size() > 0)
	{
		std::vector<czr::block_hash> next_search_hashs;

		for (czr::block_hash const & hash : search_hashs)
		{
			std::unique_ptr<czr::block> block(store.block_get(transaction_a, hash));
			assert(block != nullptr);

			for (czr::block_hash const & p_hash : block->parents())
			{
				if (searched_hashs.find(p_hash) != searched_hashs.end())
					continue;
				searched_hashs.insert(p_hash);

				if (hash == earlier_hash)
					return true;

				czr::block_state p_state;
				bool p_state_error(store.block_state_get(transaction_a, p_hash, p_state));
				assert(!p_state_error);

				if (!p_state.is_on_main_chain && p_state.level > earlier_state.level)
					next_search_hashs.push_back(p_hash);
			}
		}

		search_hashs = next_search_hashs;
	}

	return false;
}

bool czr::graph::go_down_check_included(MDB_txn * transaction_a, czr::block_hash const & later_hash, std::vector<czr::block_hash> const &  earlier_hashs)
{
	czr::block_state later_state;
	bool later_state_error(store.block_state_get(transaction_a, later_hash, later_state));
	assert(!later_state_error);

	std::unordered_set<czr::block_hash> searched_hashs;
	std::vector<czr::block_hash> search_hashs(earlier_hashs);
	while (search_hashs.size() > 0)
	{
		std::vector<czr::block_hash> next_search_hashs;

		for (czr::block_hash const & hash : search_hashs)
		{
			//get children
			for (czr::store_iterator i(store.block_child_begin(transaction_a, czr::block_child_key(hash,0))), n(nullptr); i != n ; ++i)
			{
				if (i->first.uint256() != hash)
					break;

				czr::block_hash c_hash(i->second.uint256());
				if (searched_hashs.find(c_hash) != searched_hashs.end())
					continue;
				searched_hashs.insert(c_hash);

				if (hash == later_hash)
					return true;

				czr::block_state p_state;
				bool p_state_error(store.block_state_get(transaction_a, c_hash, p_state));
				assert(!p_state_error);

				if (!p_state.is_on_main_chain && p_state.level > later_state.level)
					next_search_hashs.push_back(c_hash);
			}
		}

		search_hashs = next_search_hashs;
	}

	return false;
}

