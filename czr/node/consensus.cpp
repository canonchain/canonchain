
#include <czr/node/consensus.hpp>

czr::consensus::consensus(czr::node & node_a, czr::ledger & ledger_a, MDB_txn * transaction, std::function<void(std::shared_ptr<czr::block>)> block_stable_observer_a) :
	node(node_a),
	ledger(ledger_a),
	transaction(transaction),
	block_stable_observer(block_stable_observer_a)
{
}

czr::consensus::~consensus()
{
}

czr::process_return czr::consensus::process(czr::publish const & message)
{
	auto result(validate(message));
	if (result.code == process_result::ok)
		save_block(*message.block, result.is_fork);

	return result;
}

czr::process_return czr::consensus::validate(czr::publish const & message)
{
	czr::process_return result;
	if (message.block == nullptr)
	{
		result.code = czr::process_result::invalid_message;
		result.err_msg = "block is null";
		return result;
	}

	std::unique_ptr<czr::block> block(message.block.get());
	auto hash(block->hash());

	//todo:to check if block is in invalid block cache;

	if (validate_message(block->hashables.from, hash, block->signature))
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = "invalid signature";
		return result;
	}

	auto exists(ledger.store.block_exists(transaction, hash));
	if (exists)
	{
		result.code = czr::process_result::old;
		return result;
	}

#pragma region validate hash_tree_summary

	if (!message.summary_hash.is_zero())
	{
		//todo:check if summary_hash exists in hash_tree_summary
		bool hash_tree_summary_exists;
		if (!exists)
		{
			result.code = czr::process_result::missing_hash_tree_summary;
			return result;
		}

		//get parent summary hashs
		std::vector<czr::summary_hash> p_summary_hashs;
		for (czr::block_hash & pblock_hash : block->parents_and_previous())
		{
			czr::summary_hash p_summary_hash;
			bool exists;	//todo:get p_summary_hash from hash_tree_summary
			if (!exists)
			{
				exists = !ledger.store.block_summary_get(transaction, pblock_hash, p_summary_hash);
			}

			if (!exists)
			{
				result.code = czr::process_result::invalid_message;
				result.err_msg = boost::str(boost::format("Parent %1% 's summary not found") % pblock_hash.to_string());
				return result;
			}

			p_summary_hashs.push_back(p_summary_hash);
		}

		std::set<czr::summary_hash> summary_skiplist;
		if (message.block_skiplist.size() > 0)
		{
			//get summary skiplist hashs
			for (czr::block_hash const & sl_block_hash : message.block_skiplist)
			{
				czr::summary_hash sl_summary_hash;
				bool exists;	//todo:get sl_summary_hash from hash_tree_summary
				if (!exists)
				{
					exists = !ledger.store.block_summary_get(transaction, sl_block_hash, sl_summary_hash);
				}

				if (!exists)
				{
					result.code = czr::process_result::invalid_message;
					result.err_msg = boost::str(boost::format("Skiplist block %1% 's summary not found") % sl_block_hash.to_string());
					return result;
				}

				summary_skiplist.insert(sl_summary_hash);
			}
		}

		czr::summary_hash calc_summary_hash = gen_summary_hash(hash, p_summary_hashs, summary_skiplist, 
			message.is_fork, message.is_invalid, message.is_fail, message.from_state, message.to_state);

		if (message.summary_hash != calc_summary_hash)
		{
			result.code = czr::process_result::invalid_message;
			result.err_msg = boost::str(boost::format("Invalid message summaryhash: %1%, calculated summary hash: %2%") % message.summary_hash.to_string() % calc_summary_hash.to_string());
			return result;
		}
	}

#pragma endregion

#pragma region validate parents and previous

	//check size
	size_t parents_and_pervious_size(block->parents_and_previous().size());
	if (parents_and_pervious_size == 0 || parents_and_pervious_size > czr::max_parents_and_pervious_size)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("Invalid parent and perviou size: %1%") % parents_and_pervious_size);
		return result;
	}

	//check missing parents and previous 
	for (czr::block_hash & pblock_hash : block->parents_and_previous())
	{
		if (!ledger.store.block_exists(transaction, pblock_hash))
		{
			result.missing_parents_and_previous.push_back(pblock_hash);
			continue;
		}
	}
	if (result.missing_parents_and_previous.size() > 0)
	{
		//todo:check any of missing parents is known bad block, if so return invalid block;

		result.code = czr::process_result::missing_parents_and_previous;
		return result;
	}

	//check pervious
	if (!block->previous().is_zero())
	{
		std::unique_ptr<czr::block> previous_block = ledger.store.block_get(transaction, block->previous());
		assert(previous_block != nullptr);

		if (previous_block->hashables.from != block->hashables.from)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("current from %1% not equal to pervious from %2%") % block->hashables.from.to_string() % previous_block->hashables.from.to_string());
			return result;
		}
	}

	//check parents
	czr::block_hash pre_pblock_hash;
	for (czr::block_hash & pblock_hash : block->hashables.parents)
	{
		if (pblock_hash <= pre_pblock_hash)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = "parent hash not ordered";
			return result;
		}
		pre_pblock_hash = pblock_hash;

		//todo:graph.compareUnitsByProps ?
	}

#pragma endregion

#pragma region check last summary

	czr::block_hash last_summary_block_hash(block->hashables.last_summary_block);
	czr::block_state last_summary_block_state;
	bool last_summary_block_exists(!ledger.store.block_state_get(transaction, block->hashables.last_summary_block, last_summary_block_state));
	if (!last_summary_block_exists)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% not exists") % block->hashables.last_summary_block.to_string());
		return result;
	}

	if (!last_summary_block_state.is_on_main_chain)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not on main chain") % block->hashables.last_summary_block.to_string());
		return result;
	}

	uint64_t max_parent_limci;
	for (czr::block_hash & pblock_hash : block->parents_and_previous())
	{
		czr::block_state pblock_state;
		bool error(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
		assert(!error);
		if (pblock_state.level > 0) //not genesis
		{
			assert(pblock_state.latest_included_mc_index);
			if (*pblock_state.latest_included_mc_index > max_parent_limci)
				max_parent_limci = *pblock_state.latest_included_mc_index;
		}
	}

	assert(last_summary_block_state.main_chain_index);
	uint64_t last_summary_mci = *last_summary_block_state.main_chain_index;
	if (last_summary_mci > max_parent_limci)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not included in parents and previous") % block->hashables.last_summary_block.to_string());
		return result;
	}

#pragma endregion

#pragma region validate skiplist

	czr::block_hash prev_sl_block_hash;
	for (czr::block_hash const & sl_block_hash : message.block_skiplist)
	{
		if (sl_block_hash <= prev_sl_block_hash)
		{
			result.code = czr::process_result::invalid_message;
			result.err_msg = "skiplist block hashs not ordered";
			return result;
		}
		prev_sl_block_hash = sl_block_hash;

		czr::block_state sl_block_state;
		bool sl_block_state_exists(!ledger.store.block_state_get(transaction, sl_block_hash, sl_block_state));
		if (!sl_block_state_exists)
		{
			result.code = czr::process_result::invalid_message;
			result.err_msg = boost::str(boost::format("skiplist block %1% not found") % sl_block_hash.to_string());
			return result;
		}

		// if not stable, can't check that it is on MC as MC is not stable in its area yet
		if (sl_block_state.is_stable)
		{
			if (!sl_block_state.is_on_main_chain)
			{
				result.code = czr::process_result::invalid_message;
				result.err_msg = boost::str(boost::format("skiplist block %1% is not on main chain") % sl_block_hash.to_string());
				return result;
			}

			assert(sl_block_state.main_chain_index);
			if (*sl_block_state.main_chain_index % czr::skiplist_divisor != 0)
			{
				result.code = czr::process_result::invalid_message;
				result.err_msg = boost::str(boost::format("skiplist block %1% MCI is not divisible by %2%") % sl_block_hash.to_string() % czr::skiplist_divisor);
				return result;
			}
		}
	}

#pragma endregion

#pragma region  validate witness list

	czr::witness_list_info wl_info;
	if (!block->hashables.witness_list_block.is_zero())
	{
		//check if wl block exists
		czr::block_state wl_block_state;
		bool wl_block_state_exists(!ledger.store.block_state_get(transaction, block->hashables.witness_list_block, wl_block_state));
		if (!wl_block_state_exists)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% not found") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block is stable
		if (!wl_block_state.is_stable)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% is not stable") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block is fork or invalid
		if (wl_block_state.is_fork || wl_block_state.is_invalid)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% is fork or invalid") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block come before last summary
		assert(wl_block_state.main_chain_index);
		if (*wl_block_state.main_chain_index > last_summary_mci)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% must come before last summary") % block->hashables.witness_list_block.to_string());
			return result;
		}

		bool wl_info_exists(!ledger.store.block_witnesslist_get(transaction, block->hashables.witness_list_block, wl_info));
		if (!wl_info_exists)
		{
			result.code = czr::process_result::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% has no witness") % block->hashables.witness_list_block.to_string());
			return result;
		}
	}
	else if (block->hashables.witness_list.size() == czr::witness_count)
	{
		//check witness list order
		czr::account prev_witness(block->hashables.witness_list[0]);
		for (int i = 1; i < block->hashables.witness_list.size(); i++)
		{
			czr::account curr_witness = block->hashables.witness_list[i];
			if (curr_witness <= prev_witness)
			{
				result.code = czr::process_result::invalid_block;
				result.err_msg = "witness_list not ordered or duplicates";
				return result;
			}
			prev_witness = curr_witness;
		}

		//check that all witnesses are already known and their blocks are good and stable
		for (czr::account & witness : block->hashables.witness_list)
		{
			czr::account_info info;
			bool exists(!ledger.store.account_get(transaction, witness, info));
			if (!exists || !info.first_good_stable_mci || *info.first_good_stable_mci > last_summary_mci)
			{
				result.code = czr::process_result::invalid_block;
				result.err_msg = boost::str(boost::format("witnesses %1% are not stable, not good, or don't come before last summary") % witness.to_string());
				return result;
			}
		}

		wl_info = witness_list_info(block->hashables.witness_list);
	}
	else
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = "no witnesses or not enough witnesses";
		return result;
	}

	//check best parent
	czr::block_hash best_pblock_hash(determine_best_parent(block->parents_and_previous(), wl_info));
	if (best_pblock_hash.is_zero())
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = "no compatible best parent";
		return result;
	}

	//check witness list mutations along mc
	bool is_mutations_ok(check_witness_list_mutations_along_mc(best_pblock_hash, *block));
	if (!is_mutations_ok)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = "too many witness list mutations along mc";
		return result;
	}

	//check witnessed level did not retreat
	uint64_t witnessed_level(determine_witness_level(best_pblock_hash, wl_info));
	czr::block_state best_pblock_state;
	bool best_pblock_state_error(ledger.store.block_state_get(transaction, best_pblock_hash, best_pblock_state));
	assert(!best_pblock_state_error);
	if (witnessed_level < best_pblock_state.witnessed_level)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("witnessed level retreats from &1& to &2&") % best_pblock_state.witnessed_level % witnessed_level);
		return result;
	}

#pragma endregion

#pragma region  check if last summary block is stable in view of parents and previous
	bool is_last_summary_stable = check_stable_from_view_of_parents_and_previous(last_summary_block_hash, hash);
	if (!is_last_summary_stable)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not stable in view of parent") % block->hashables.last_summary_block.to_string());
		return result;
	}

	if (!last_summary_block_state.is_stable)
	{
		advance_mc_stable_block(last_summary_block_hash, last_summary_mci);
	}

	//check last summary hash
	czr::summary_hash last_summary_hash;
	bool last_summary_exists(!ledger.store.block_summary_get(transaction, last_summary_block_hash, last_summary_hash));
	if (!last_summary_exists)
	{
		auto msg(boost::str(boost::format("last summary block %1% is stable but summary not found") % last_summary_block_hash.to_string()));
		BOOST_LOG(node.log) << msg;
		throw std::runtime_error(msg);
	}
	if (last_summary_hash != block->hashables.last_summary)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary %1% and last summary block %2% do not match") % block->hashables.last_summary.to_string() % block->hashables.last_summary_block.to_string());
		return result;
	}

	//check last summary mci retreat
	uint64_t max_parent_last_summary_mci;
	for (czr::block_hash & pblock_hash : block->parents_and_previous())
	{
		std::unique_ptr<czr::block> pblock = ledger.store.block_get(transaction, pblock_hash);
		assert(pblock != nullptr);
		czr::block_state parent_last_summary_state;
		bool error(ledger.store.block_state_get(transaction, pblock->hashables.last_summary_block, parent_last_summary_state));
		assert(!error);
		assert(parent_last_summary_state.main_chain_index);
		if (*parent_last_summary_state.main_chain_index > max_parent_last_summary_mci)
			max_parent_last_summary_mci = *parent_last_summary_state.main_chain_index;
	}
	if (last_summary_mci < max_parent_last_summary_mci)
	{
		result.code = czr::process_result::invalid_block;
		result.err_msg = boost::str(boost::format("last summary mci %1% retreat, max parent last summary mci %2%") % last_summary_mci % max_parent_last_summary_mci);
		return result;
	}

#pragma endregion
	
	czr::account_info info;
	auto account_exists(!ledger.store.account_get(transaction, block->hashables.from, info));
	bool is_fork;
	if (account_exists)
	{
		// Account already exists
		if (block->previous().is_zero() || block->previous() != info.head)
		{
			is_fork = true;
		}
	}

	result.code = czr::process_result::ok;
	result.is_fork = is_fork;
	result.account = block->hashables.from;
	result.amount = block->hashables.amount.number();
}

void czr::consensus::save_block(czr::block const & block_a, bool const & is_fork)
{
	auto block_hash(block_a.hash());
	auto hashables(block_a.hashables);

	czr::witness_list_info wl_info(ledger.block_witness_list(transaction, block_a));

	uint64_t max_parent_level;
	for (czr::block_hash & pblock_hash : block_a.parents_and_previous())
	{
		std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction, pblock_hash));
		czr::block_state pblock_state;
		auto pstate_error(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
		assert(!pstate_error);

		//remove parent blocks from free
		czr::free_key f_key(pblock_state.witnessed_level, pblock_state.level, pblock_hash);
		ledger.store.free_del(transaction, f_key);
		pblock_state.is_free = false;
		ledger.store.block_state_put(transaction, pblock_hash, pblock_state);

		if (pblock_state.level > max_parent_level)
		{
			max_parent_level = pblock_state.level;
		}
	}

	//best parent
	czr::block_hash best_pblock_hash(determine_best_parent(block_a.parents_and_previous(), wl_info));

	//witnessed level
	uint64_t witnessed_level(determine_witness_level(best_pblock_hash, wl_info));

	//save block state
	czr::block_state state;
	state.is_fork = is_fork;
	state.is_free = true;
	state.best_parent = best_pblock_hash;
	state.level = max_parent_level + 1;
	state.witnessed_level = witnessed_level;
	state.creation_date = std::chrono::system_clock::now();
	ledger.store.block_state_put(transaction, block_hash, state);
	//save free
	ledger.store.free_put(transaction, czr::free_key(state.witnessed_level, state.level, block_hash));
	//save unstable
	ledger.store.unstable_put(transaction, block_hash);
	//save block
	ledger.store.block_put(transaction, block_hash, block_a);

	if (!state.is_fork)
	{
		czr::account_info info;
		ledger.store.account_get(transaction, block_a.hashables.from, info);
		ledger.change_account_latest(transaction, block_a.hashables.from, block_hash, info.block_count + 1);
	}
	else
	{
		if (!block_a.previous().is_zero())
		{
			czr::block_state previous_state;
			ledger.store.block_state_get(transaction, block_a.previous(), previous_state);
			if (previous_state.is_fork && !previous_state.is_stable)
			{
				czr::uint256_union fork_successor_hash;
				bool exists(!ledger.store.fork_successor_get(transaction, block_a.previous(), fork_successor_hash));
				if (!exists)
				{
					ledger.store.fork_successor_put(transaction, block_a.previous(), block_hash);
				}
			}
		}
	}

	update_main_chain(block_a);
}

void czr::consensus::update_main_chain(czr::block const & block_a)
{
	//search best free block by witnessed_level desc, level asc, block hash asc
	czr::store_iterator free_iter(ledger.store.free_begin(transaction));
	assert(free_iter != czr::store_iterator(nullptr));
	czr::free_key free_key = free_iter->first.value;
	czr::block_hash free_block_hash(free_key.hash_asc);

	czr::block_state free_block_state;
	ledger.store.block_state_get(transaction, free_block_hash, free_block_state);
	if (free_block_state.level == 0) //genesis block
		return;

	czr::block_hash last_best_pblock_state_hash(free_block_hash);
	czr::block_state last_best_pblock_state(free_block_state);
	using pair_block_hash_state = std::pair<czr::block_hash, czr::block_state>;

	std::unique_ptr<std::list<pair_block_hash_state>> new_mc_block_states(new std::list<pair_block_hash_state>);
	while (!last_best_pblock_state.is_on_main_chain)
	{
		new_mc_block_states->push_front(std::make_pair(last_best_pblock_state_hash, last_best_pblock_state));

		//get pre best parent block
		last_best_pblock_state_hash = last_best_pblock_state.best_parent;
		bool pre_best_pblock_error(ledger.store.block_state_get(transaction, last_best_pblock_state_hash, last_best_pblock_state));
		assert(!pre_best_pblock_error);
	}
	assert(last_best_pblock_state.main_chain_index);

	uint64_t last_mc_index(*last_best_pblock_state.main_chain_index);

#pragma region delete old main chain block whose main chain index larger than last_mc_index

	for (czr::store_iterator i(ledger.store.main_chain_begin(transaction, last_mc_index + 1)), n(nullptr); i != n; ++i)
	{
		czr::block_hash old_mc_block_hash(i->second.uint256());
		czr::block_state old_mc_block_state;
		bool old_mc_block_error(ledger.store.block_state_get(transaction, old_mc_block_hash, old_mc_block_state));
		assert(!old_mc_block_error && !old_mc_block_state.is_stable);

		old_mc_block_state.is_on_main_chain = false;
		old_mc_block_state.main_chain_index = boost::none;
		ledger.store.block_state_put(transaction, old_mc_block_hash, old_mc_block_state);

		uint64_t old_mc_block_mc_index(i->first.uint64());
		ledger.store.main_chain_del(transaction, old_mc_block_mc_index);
	}

#pragma endregion

#pragma region update main chain index

	uint64_t mc_index(last_mc_index);
	for (auto iter(new_mc_block_states->begin()); iter != new_mc_block_states->end(); iter++)
	{
		auto pair(*iter);
		mc_index++;
		czr::block_hash new_mc_block_hash(pair.first);
		czr::block_state new_mc_block_state(pair.second);
		new_mc_block_state.is_on_main_chain = true;
		new_mc_block_state.main_chain_index = mc_index;
		ledger.store.block_state_put(transaction, new_mc_block_hash, new_mc_block_state);
		ledger.store.main_chain_put(transaction, mc_index, new_mc_block_hash);

		std::shared_ptr<std::unordered_set<czr::block_hash>> updated_hashs;
		update_parent_mc_index(new_mc_block_hash, mc_index, updated_hashs);
	}

#pragma endregion

#pragma region update latest included mc index

	//get from unstable blocks where main_chain_index > last_main_chain_index or main_chain_index == null
	std::unique_ptr<std::unordered_map <czr::block_hash, czr::block_state>> to_update_limci_blocks(new std::unordered_map <czr::block_hash, czr::block_state>);
	for (czr::store_iterator i(ledger.store.unstable_begin(transaction)), n(nullptr); i != n; ++i)
	{
		czr::block_hash block_hash(i->first.uint256());
		czr::block_state state;
		bool error(ledger.store.block_state_get(transaction, block_hash, state));
		assert(!error);
		if (!state.main_chain_index || (*state.main_chain_index) > last_mc_index)
			to_update_limci_blocks->insert(std::make_pair(block_hash, state));
	}

	while (to_update_limci_blocks->size() > 0)
	{
		std::unique_ptr<std::vector<czr::block_hash>> updated_limci_blocks(new std::vector<czr::block_hash>);
		for (auto iter(to_update_limci_blocks->begin()); iter != to_update_limci_blocks->end(); iter++)
		{
			auto pair(*iter);
			czr::block_hash block_hash(pair.first);
			std::unique_ptr<czr::block> block = ledger.store.block_get(transaction, block_hash);
			assert(block != nullptr);

			bool is_parent_ready(true);
			boost::optional<uint64_t> max_limci;
			for (czr::block_hash & pblock_hash : block->parents_and_previous())
			{
				czr::block_state pblock_state;
				bool pblock_state_error(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
				assert(!pblock_state_error);

				if (pblock_state.is_on_main_chain)
				{
					assert(pblock_state.main_chain_index);
					if (!max_limci || *max_limci < *pblock_state.main_chain_index)
						max_limci = pblock_state.main_chain_index;
				}
				else
				{
					if (!pblock_state.latest_included_mc_index)
					{
						is_parent_ready = false;
						break;
					}
					if (!max_limci || *max_limci < *pblock_state.latest_included_mc_index)
						max_limci = pblock_state.latest_included_mc_index;
				}
			}

			if (!is_parent_ready)
				continue;

			assert(max_limci);
			czr::block_state block_state;
			bool block_state_error(ledger.store.block_state_get(transaction, block_hash, block_state));
			assert(!block_state_error);
			block_state.latest_included_mc_index = max_limci;
			ledger.store.block_state_put(transaction, block_hash, block_state);

			updated_limci_blocks->push_back(block_hash);
		}

		for (auto iter(updated_limci_blocks->begin()); iter != updated_limci_blocks->end(); iter++)
			to_update_limci_blocks->erase(*iter);
	}

#pragma endregion

	check_mc_stable_block();
}

void czr::consensus::check_mc_stable_block()
{
	//get last stable main chain block
	uint64_t last_stable_mci(ledger.store.last_stable_mci_get(transaction));
	assert(last_stable_mci != 0);
	czr::block_hash last_stable_block_hash;
	bool mc_error(ledger.store.main_chain_get(transaction, last_stable_mci, last_stable_block_hash));
	assert(!mc_error);
	std::unique_ptr<czr::block> last_stable_block(ledger.store.block_get(transaction, last_stable_block_hash));
	assert(last_stable_block != nullptr);

	//get witness list of last stable block
	czr::witness_list_info last_stable_block_wl_info(ledger.block_witness_list(transaction, *last_stable_block));

	//get free main chain block (the lastest mc block)
	czr::store_iterator mc_iter(ledger.store.main_chain_rbegin(transaction));
	assert(mc_iter != czr::store_iterator(nullptr));
	czr::block_hash free_mc_block_hash(mc_iter->second.uint256());
	uint64_t min_wl(find_mc_min_wl(free_mc_block_hash, last_stable_block_wl_info));

	bool is_stable;

#pragma region check is stable

	czr::block_hash mc_child_hash;
	std::shared_ptr<std::vector<czr::block_hash>> branch_child_hashs(new std::vector<czr::block_hash>);
	find_unstable_child_blocks(last_stable_block_hash, mc_child_hash, branch_child_hashs);

	if (branch_child_hashs->size() == 0)
	{
		//non branch
		czr::block_state mc_child_state;
		bool state_error(ledger.store.block_state_get(transaction, mc_child_hash, mc_child_state));
		assert(!state_error);

		if (min_wl >= mc_child_state.witnessed_level)
			is_stable = true;
	}
	else
	{
		//branch
		std::unique_ptr<std::vector<czr::block_hash>> search_hash_list;
		uint64_t branch_max_level;
		for (auto i(branch_child_hashs->begin()); i != branch_child_hashs->end(); i++)
		{
			czr::block_hash branch_child_hash(*i);
			czr::block_state branch_child_state;
			bool error(ledger.store.block_state_get(transaction, branch_child_hash, branch_child_state));
			assert(!error);

			if (branch_child_state.level > branch_max_level)
				branch_max_level = branch_child_state.level;

			if (!branch_child_state.is_free)
			{
				search_hash_list->push_back(branch_child_hash);
			}
		}
		czr::store_iterator branch_child_iter_end(nullptr);

		while (search_hash_list->size() > 0)
		{
			std::unique_ptr<std::vector<czr::block_hash>> next_search_hash_list(new std::vector<czr::block_hash>);

			for (auto iter(search_hash_list->begin()); iter != search_hash_list->end(); iter++)
			{
				czr::block_hash hash(*iter);
				czr::block_state block_state;
				bool error(ledger.store.block_state_get(transaction, hash, block_state));
				assert(!error);

				czr::store_iterator branch_child_iter(ledger.store.block_child_begin(transaction, czr::block_child_key(hash, 0)));
				while (true)
				{
					if (branch_child_iter == branch_child_iter_end)
						break;

					czr::block_child_key key(branch_child_iter->first);
					if (key.hash != hash)
						break;

					czr::block_state branch_child_state;
					bool branch_child_state_error(ledger.store.block_state_get(transaction, key.child_hash, branch_child_state));
					assert(!branch_child_state_error);

					if (branch_child_state.best_parent == key.hash)
					{
						if (branch_child_state.witnessed_level > block_state.witnessed_level 
							&& branch_child_state.level > branch_max_level)
							branch_max_level = branch_child_state.level;

						if(!branch_child_state.is_free)
							next_search_hash_list->push_back(key.child_hash);
					}

					++branch_child_iter;
				}
			}

			search_hash_list = std::move(next_search_hash_list);
		}

		if (min_wl >= branch_max_level)
			is_stable = true;
	}

#pragma endregion

	if (!is_stable)
		return;

	//update stable block
	czr::block_hash mc_stable_hash(mc_child_hash);
	uint64_t new_last_stable_mci(last_stable_mci + 1);
	advance_mc_stable_block(mc_stable_hash, new_last_stable_mci);

	check_mc_stable_block();
}

void czr::consensus::advance_mc_stable_block(czr::block_hash const & mc_stable_hash, uint64_t const & mci)
{
	std::shared_ptr<std::set<czr::block_hash>> stable_block_hashs(new std::set<czr::block_hash>); //order by block hash
	update_stable_block(mc_stable_hash, mci, stable_block_hashs);

#pragma region handle fork block

	std::shared_ptr<std::unordered_set<czr::block_hash>> handle_fork_hashs(new std::unordered_set<czr::block_hash>);
	for (auto iter(stable_block_hashs->begin()); iter != stable_block_hashs->end(); iter++)
	{
		handle_fork_hashs->insert(*iter);
	}

	while (handle_fork_hashs->size() > 0)
	{
		std::unique_ptr<std::vector<czr::block_hash>> handled_hashs;

		for (auto iter(handle_fork_hashs->begin()); iter != handle_fork_hashs->end(); iter++)
		{
			czr::block_hash stable_block_hash = *iter;
			std::unique_ptr<czr::block> stable_block = ledger.store.block_get(transaction, stable_block_hash);
			assert(stable_block != nullptr);

			czr::block_hash previous_hash(stable_block->previous());
			czr::block_state previous_state;
			if (!previous_hash.is_zero())
			{
				//previous not handled, handle previous first
				if (handle_fork_hashs->find(previous_hash) != handle_fork_hashs->end())
					continue;
			}

			czr::block_state stable_block_state;
			bool block_state_error(ledger.store.block_state_get(transaction, stable_block_hash, stable_block_state));
			assert(!block_state_error);

			if (!previous_hash.is_zero() && previous_state.is_fork)
				assert(stable_block_state.is_fork);
			else
			{
				if (stable_block_state.is_fork)
				{
					std::unique_ptr<czr::block> successor(ledger.successor(transaction, stable_block->root()));
					czr::block_hash successor_hash(successor->hash());
					assert(successor != nullptr && successor_hash != stable_block_hash);
					czr::block_state successor_state;
					bool successor_state_error(ledger.store.block_state_get(transaction, successor_hash, successor_state));
					assert(!successor_state_error);

					if (!successor_state.main_chain_index
						|| *successor_state.main_chain_index > *stable_block_state.main_chain_index
						|| (*successor_state.main_chain_index == *stable_block_state.main_chain_index && successor_hash.number() > stable_block_hash.number()))
					{
						assert(!successor_state.is_fork);

						//rollbock account info
						rollback(successor_hash);

						//change successor
						change_successor(stable_block_hash);
					}
				}
			}

			handled_hashs->push_back(stable_block_hash);
		}

		for (auto iter(handled_hashs->begin()); iter != handled_hashs->end(); iter++)
		{
			handle_fork_hashs->erase(*iter);
		}
	}

#pragma endregion

#pragma region handle stable block

	while (stable_block_hashs->size() > 0)
	{
		std::shared_ptr<std::unordered_set<czr::block_hash>> handled_stable_block_hashs(new std::unordered_set<czr::block_hash>);

		for (auto iter(stable_block_hashs->begin()); iter != stable_block_hashs->end(); iter++)
		{
			czr::block_hash block_hash = *iter;
			std::unique_ptr<czr::block> block(ledger.store.block_get(transaction, block_hash));
			assert(block != nullptr);

			//if parent not handled, handle parent first;
			auto parents_and_previous(block->parents_and_previous());
			bool parent_not_handled;
			for (auto i(parents_and_previous.begin()); i != parents_and_previous.end(); i++)
			{
				czr::block_hash pblock_hash(*i);
				auto it(stable_block_hashs->find(pblock_hash));
				if (it != stable_block_hashs->end())
				{
					parent_not_handled = true;
					break;
				}
			}
			if (parent_not_handled)
			{
				continue;
			}

			czr::block_state block_state;
			bool block_state_error(ledger.store.block_state_get(transaction, block_hash, block_state));
			assert(!block_state_error);

			bool is_invalid;
			bool is_fail;
			if (!block_state.is_fork)
			{
				czr::account_state pre_from_state;
				bool exist(!ledger.store.latest_account_state_get(transaction, block->hashables.from, pre_from_state));
				czr::uint128_t pre_from_balance(exist ? pre_from_state.balance.number() : 0);
				czr::uint128_t amount(block->hashables.amount.number());
				czr::uint128_t fee; //todo:caculate fee///////////////

				is_invalid = pre_from_balance < fee;
				if (!is_invalid)
				{
					is_fail = pre_from_balance < amount + fee;

					//from account state
					czr::uint128_t from_balance = is_fail ? pre_from_balance - fee : pre_from_balance - amount - fee;
					czr::account_state from_state(block->hashables.from, block_hash, pre_from_state.hash(), from_balance);
					block_state.from_state = from_state.hash();
					ledger.store.account_state_put(transaction, block_state.from_state, from_state);
					ledger.store.latest_account_state_put(transaction, block->hashables.from, from_state);

					//try set account good stable mci
					ledger.try_set_account_good_stable_mci(transaction, block->hashables.from, mci);

					if (!is_fail)
					{
						//to account state
						czr::account_state pre_to_state;
						bool exist(!ledger.store.latest_account_state_get(transaction, block->hashables.to, pre_to_state));
						czr::uint128_t pre_to_balance(exist ? pre_to_state.balance.number() : 0);
						czr::uint128_t to_balance = pre_to_balance + amount;
						czr::account_state to_state(block->hashables.to, block_hash, pre_to_state.hash(), to_balance);
						block_state.to_state = to_state.hash();
						ledger.store.account_state_put(transaction, block_state.to_state, to_state);
						ledger.store.latest_account_state_put(transaction, block->hashables.to, to_state);
					}

					//save witness list
					if (block->hashables.witness_list.size() > 0)
					{
						czr::witness_list_info wl_info(block->hashables.witness_list);
						ledger.store.block_witnesslist_put(transaction, block_hash, wl_info);

						auto wl_hash(wl_info.hash());
						if (!ledger.store.witnesslisthash_block_exists(transaction, wl_hash))
						{
							//save witness list hash -> block hash
							ledger.store.witnesslisthash_block_put(transaction, wl_hash, block_hash);
						}
					}
				}
			}

			if (block_state.is_fork || is_invalid)
			{
				//todo:clear content;
			}

			block_state.is_invalid = is_invalid;
			block_state.is_fail = is_fail;
			block_state.is_stable = true;
			ledger.store.block_state_put(transaction, block_hash, block_state);

#pragma region summary

			//parent summary hashs
			std::vector<czr::summary_hash> p_summary_hashs;
			for (czr::block_hash & pblock_hash : block->parents_and_previous())
			{
				czr::summary_hash p_summary_hash;
				bool p_summary_hash_error(ledger.store.block_summary_get(transaction, pblock_hash, p_summary_hash));
				assert(!p_summary_hash_error);

				p_summary_hashs.push_back(p_summary_hash);
			}

			//skip list
			std::vector<czr::block_hash> block_skiplist;
			std::set<czr::summary_hash> summary_skiplist;
			if (block_state.is_on_main_chain)
			{
				assert(block_state.main_chain_index);
				std::vector<uint64_t> skip_list_mcis = cal_skip_list_mcis(*block_state.main_chain_index);
				for (uint64_t & mci : skip_list_mcis)
				{
					czr::block_hash sl_block_hash;
					bool sl_block_hash_error(ledger.store.main_chain_get(transaction, mci, sl_block_hash));
					assert(!sl_block_hash_error);
					block_skiplist.push_back(sl_block_hash);

					czr::summary_hash sl_summary_hash;
					bool sl_summary_hash_error(ledger.store.block_summary_get(transaction, sl_block_hash, sl_summary_hash));
					assert(!sl_summary_hash_error);
					summary_skiplist.insert(sl_summary_hash);
				}
			}
			ledger.store.skiplist_put(transaction, block_hash, czr::skiplist_info(block_skiplist));

			//summary hash
			czr::summary_hash summary_hash = gen_summary_hash(block_hash, p_summary_hashs, summary_skiplist,
				block_state.is_fork, block_state.is_invalid, block_state.is_fail, block_state.from_state, block_state.to_state);
			ledger.store.block_summary_put(transaction, block_hash, summary_hash);
			ledger.store.summary_block_put(transaction, summary_hash, block_hash);

#pragma endregion

			//todo:delete summary_hash from hash_tree_summary

			block_stable_observer(std::move(block));

			handled_stable_block_hashs->insert(block_hash);
		}

		for (auto iter(handled_stable_block_hashs->begin()); iter != handled_stable_block_hashs->end(); iter++)
		{
			stable_block_hashs->erase(*iter);
		}
	}

#pragma endregion

	//update last stable main chain index
	ledger.store.last_stable_mci_put(transaction, mci);
}

//Rollback blocks until `block_hash' is not fork
void czr::consensus::rollback(czr::block_hash const & block_hash)
{
	assert(ledger.store.block_exists(transaction, block_hash));

	auto account_l(ledger.block_account(transaction, block_hash));
	czr::block_state state;
	bool state_error(ledger.store.block_state_get(transaction, block_hash, state));
	assert(!state_error);
	if (state.is_fork)
		return;

	while (true)
	{
		czr::account_info info;
		auto latest_error(ledger.store.account_get(transaction, account_l, info));
		assert(!latest_error);

		czr::block_hash latest_hash(info.head);
		auto latest_block(ledger.store.block_get(transaction, latest_hash));

		ledger.change_account_latest(transaction, account_l, latest_block->previous(), info.block_count - 1);

		if (!latest_block->previous().is_zero())
			ledger.store.block_successor_clear(transaction, latest_block->previous());

		czr::block_state latest_state;
		bool state_error(ledger.store.block_state_get(transaction, latest_hash, latest_state));
		assert(!state_error);
		latest_state.is_fork = true;
		ledger.store.block_state_put(transaction, latest_hash, latest_state);

		if (latest_hash == block_hash)
			break;
	}
}

void czr::consensus::change_successor(czr::block_hash const & block_hash)
{
	czr::block_hash new_successor_hash(block_hash);
	std::unique_ptr<czr::block> new_successor;
	czr::block_state new_successor_state;

	while (true)
	{
		new_successor = ledger.store.block_get(transaction, new_successor_hash);
		assert(new_successor != nullptr);
		bool new_successor_state_error(ledger.store.block_state_get(transaction, new_successor_hash, new_successor_state));
		assert(!new_successor_state_error);

		//update account info
		czr::account_info info;
		ledger.store.account_get(transaction, new_successor->hashables.from, info);
		ledger.change_account_latest(transaction, new_successor->hashables.from, new_successor_hash, info.block_count + 1);

		//set predecessor
		ledger.store.block_predecessor_set(transaction, *new_successor, true);

		//update state is_fork
		new_successor_state.is_fork = false;
		ledger.store.block_state_put(transaction, new_successor_hash, new_successor_state);

		//get next fork successor
		czr::block_hash fork_successor_hash;
		bool exists(!ledger.store.fork_successor_get(transaction, new_successor_hash, fork_successor_hash));
		if (!exists)
			break;
		ledger.store.fork_successor_del(transaction, new_successor_hash);

		new_successor_hash = fork_successor_hash;
	}
}

void czr::consensus::update_parent_mc_index(czr::block_hash const & hash_a, uint64_t const & mc_index, std::shared_ptr<std::unordered_set<czr::block_hash>> updated_hashs)
{
	std::unique_ptr<czr::block> block = ledger.store.block_get(transaction, hash_a);
	assert(block != nullptr);
	for (auto & pblock_hash : block->parents_and_previous())
	{
		if (updated_hashs->find(pblock_hash) != updated_hashs->end())
			continue;

		czr::block_state pblock_state;
		bool pblock_state_error(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
		assert(!pblock_state_error);
		if (pblock_state.main_chain_index && *pblock_state.main_chain_index < mc_index)
			continue;
		pblock_state.main_chain_index = mc_index;
		ledger.store.block_state_put(transaction, pblock_hash, pblock_state);

		updated_hashs->insert(pblock_hash);

		update_parent_mc_index(pblock_hash, mc_index, updated_hashs);
	}
}

void czr::consensus::update_stable_block(czr::block_hash const & block_hash, uint64_t const & mc_index, std::shared_ptr<std::set<czr::block_hash>> stable_block_hashs)
{
	//has updated
	if (stable_block_hashs->find(block_hash) != stable_block_hashs->end())
		return;

	czr::block_state state;
	bool state_error(ledger.store.block_state_get(transaction, block_hash, state));
	assert(!state_error);

	if (state.level == 0)
		return;
	assert(state.main_chain_index);
	if (*state.main_chain_index != mc_index)
		return;

	stable_block_hashs->insert(block_hash);

	std::unique_ptr<czr::block> block(ledger.store.block_get(transaction, block_hash));
	for (czr::block_hash & pblock_hash : block->parents_and_previous())
	{
		update_stable_block(pblock_hash, mc_index, stable_block_hashs);
	}
}

bool czr::consensus::check_stable_from_view_of_parents_and_previous(czr::block_hash const & check_hash, czr::block_hash const & later_hash)
{
	czr::block_state check_block_state;
	bool error(ledger.store.block_state_get(transaction, check_hash, check_block_state));
	assert(!error);

	//genesis
	if (check_block_state.level == 0)
		return true;
	if (check_block_state.is_free)
		return false;

	std::unique_ptr<czr::block> later_block(ledger.store.block_get(transaction, later_hash));
	assert(later_block != nullptr);

	//get max later limci 
	uint64_t max_later_limci;
	for (czr::block_hash & l_pblock_hash : later_block->parents_and_previous())
	{
		czr::block_state l_pblock_state;
		bool error(ledger.store.block_state_get(transaction, l_pblock_hash, l_pblock_state));
		assert(!error && l_pblock_state.latest_included_mc_index);

		if (*l_pblock_state.latest_included_mc_index > max_later_limci)
			max_later_limci = *l_pblock_state.latest_included_mc_index;
	}

	//get later best parent //test: does best parent need compatible?
	czr::witness_list_info l_wl_info(ledger.block_witness_list(transaction, *later_block));
	czr::block_hash l_best_pblock_hash(determine_best_parent(later_block->hashables.parents, l_wl_info));

	//get check block best parent's witness list
	czr::block_hash check_best_parent_hash(check_block_state.best_parent);
	std::unique_ptr<czr::block> check_best_parent_block = ledger.store.block_get(transaction, check_best_parent_hash);
	czr::witness_list_info check_wl_info(ledger.block_witness_list(transaction, *check_best_parent_block));

	//find min witness level
	uint64_t min_wl(find_mc_min_wl(l_best_pblock_hash, check_wl_info));

	//find unstable child blocks
	czr::block_hash mc_child_hash;
	std::shared_ptr<std::vector<czr::block_hash>> temp_branch_child_hashs(new std::vector<czr::block_hash>);
	find_unstable_child_blocks(check_best_parent_hash, mc_child_hash, temp_branch_child_hashs);

	//remove non-included branch children
	std::unique_ptr<std::vector<czr::block_hash>> branch_child_hashs(new std::vector<czr::block_hash>);
	for (auto i(temp_branch_child_hashs->begin()); i != temp_branch_child_hashs->end(); i++)
	{
		czr::block_hash branch_child_hash(*i);

		bool included; //todo:check later blocks include branch_child
		if (!included)
		{
			branch_child_hashs->push_back(branch_child_hash);
		}
	}

	bool is_stable;
	if (branch_child_hashs->size() == 0)
	{
		//non branch
		czr::block_state mc_child_state;
		bool state_error(ledger.store.block_state_get(transaction, mc_child_hash, mc_child_state));
		assert(!state_error);

		if (min_wl >= mc_child_state.witnessed_level)
			is_stable = true;
	}
	else
	{
		//branch
		std::unique_ptr<std::vector<czr::block_hash>> search_hash_list;
		uint64_t branch_max_level;
		for (auto i(branch_child_hashs->begin()); i != branch_child_hashs->end(); i++)
		{
			czr::block_hash branch_child_hash(*i);
			czr::block_state branch_child_state;
			bool error(ledger.store.block_state_get(transaction, branch_child_hash, branch_child_state));
			assert(!error);

			if (branch_child_state.level > branch_max_level)
				branch_max_level = branch_child_state.level;

			if (!branch_child_state.is_free)
			{
				search_hash_list->push_back(branch_child_hash);
			}
		}
		czr::store_iterator branch_child_iter_end(nullptr);

		while (search_hash_list->size() > 0)
		{
			std::unique_ptr<std::vector<czr::block_hash>> next_search_hash_list(new std::vector<czr::block_hash>);

			for (auto iter(search_hash_list->begin()); iter != search_hash_list->end(); iter++)
			{
				czr::block_hash hash(*iter);
				czr::block_state block_state;
				bool error(ledger.store.block_state_get(transaction, hash, block_state));
				assert(!error);

				czr::store_iterator branch_child_iter(ledger.store.block_child_begin(transaction, czr::block_child_key(hash, 0)));
				while (true)
				{
					if (branch_child_iter == branch_child_iter_end)
						break;

					czr::block_child_key key(branch_child_iter->first);
					if (key.hash != hash)
						break;

					czr::block_state branch_child_state;
					bool branch_child_state_error(ledger.store.block_state_get(transaction, key.child_hash, branch_child_state));
					assert(!branch_child_state_error);

					if (branch_child_state.best_parent == key.hash)
					{
						bool included; //todo:check later blocks include branch_child
						if (included)
						{
							if (branch_child_state.witnessed_level > block_state.witnessed_level
								&& branch_child_state.level > branch_max_level)
								branch_max_level = branch_child_state.level;

							if (!branch_child_state.is_free)
								next_search_hash_list->push_back(key.child_hash);
						}
					}

					++branch_child_iter;
				}
			}

			search_hash_list = std::move(next_search_hash_list);
		}

		if (min_wl >= branch_max_level)
			is_stable = true;
	}

	return is_stable;
}

void czr::consensus::find_unstable_child_blocks(czr::block_hash const & stable_hash, czr::block_hash & mc_child_hash, std::shared_ptr<std::vector<czr::block_hash>> branch_child_hashs)
{
	//get children ,filtered by children's best parent = check block's best parent
	czr::store_iterator child_iter(ledger.store.block_child_begin(transaction, czr::block_child_key(stable_hash, 0)));
	czr::store_iterator end(nullptr);
	while (true)
	{
		if (child_iter == end)
			break;
		czr::block_child_key key(child_iter->first);
		if (key.hash != stable_hash)
			break;

		czr::block_state child_state;
		bool error(ledger.store.block_state_get(transaction, key.child_hash, child_state));
		assert(!error);

		if (child_state.best_parent != stable_hash)
			continue;

		if (child_state.is_on_main_chain)
		{
			assert(mc_child_hash.is_zero());
			mc_child_hash = key.child_hash;
		}
		else
		{
			branch_child_hashs->push_back(key.child_hash);
		}

		++child_iter;
	}
	assert(!mc_child_hash.is_zero());
}

uint64_t czr::consensus::find_mc_min_wl(czr::block_hash const & best_block_hash, czr::witness_list_info const & witness_list)
{
	czr::block_state best_block_state;
	bool last_mc_block_state_error(ledger.store.block_state_get(transaction, best_block_hash, best_block_state));
	assert(!last_mc_block_state_error);

	//search up along main chain find min_wl
	uint64_t mc_end_level(best_block_state.witnessed_level);
	uint64_t min_wl(best_block_state.witnessed_level);
	czr::block_hash best_parent_block_hash(best_block_state.best_parent);
	while (true)
	{
		czr::block_state mc_block_state;
		bool mc_state_error(ledger.store.block_state_get(transaction, best_parent_block_hash, mc_block_state));
		assert(!mc_state_error);

		if (mc_block_state.level == 0 || mc_block_state.level < mc_end_level)
			break;

		std::unique_ptr<czr::block> mc_block(ledger.store.block_get(transaction, best_parent_block_hash));
		assert(mc_block != nullptr);

		if (witness_list.contains(mc_block->hashables.from)
			&& mc_block_state.witnessed_level < min_wl)
			min_wl = mc_block_state.witnessed_level;

		best_parent_block_hash = mc_block_state.best_parent;
	}

	return min_wl;
}

czr::summary_hash czr::consensus::gen_summary_hash(czr::block_hash const & block_hash, std::vector<czr::summary_hash> const & parent_hashs, 
	std::set<czr::summary_hash> const & skiplist, bool const & is_fork, bool const & is_invalid, bool const & is_fail,
	czr::account_state_hash const & from_state_hash, czr::account_state_hash const & to_state_hash)
{
	czr::summary_hash result;
	blake2b_state hash_l;
	auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
	assert(status == 0);

	blake2b_update(&hash_l, block_hash.bytes.data(), sizeof(block_hash.bytes));
	for (auto & parent : parent_hashs)
		blake2b_update(&hash_l, parent.bytes.data(), sizeof(parent.bytes));
	for (auto & s : skiplist)
		blake2b_update(&hash_l, s.bytes.data(), sizeof(s.bytes));
	blake2b_update(&hash_l, &is_fork, sizeof(is_fork));
	blake2b_update(&hash_l, &is_invalid, sizeof(is_invalid));
	blake2b_update(&hash_l, &is_fail, sizeof(is_fail));
	blake2b_update(&hash_l, from_state_hash.bytes.data(), sizeof(from_state_hash));
	blake2b_update(&hash_l, to_state_hash.bytes.data(), sizeof(to_state_hash));

	status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
	assert(status == 0);

	return result;
}

std::vector<uint64_t> czr::consensus::cal_skip_list_mcis(uint64_t const & mci)
{
	std::vector<uint64_t> skip_list_mcis;
	while (true)
	{
		uint64_t divisor = czr::skiplist_divisor;
		if (mci % divisor == 0)
		{
			skip_list_mcis.push_back(mci - divisor);
			divisor *= czr::skiplist_divisor;
		}
		else
			return skip_list_mcis;
	}
}

//best parent:compatible parent, witnessed_level DESC, level ASC, unit ASC
czr::block_hash czr::consensus::determine_best_parent(std::vector<czr::block_hash> const & pblock_hashs, czr::witness_list_info const & wl_info)
{
	czr::block_hash best_pblock_hash;
	czr::block_state best_pblock_state;
	for (czr::block_hash const & pblock_hash : pblock_hashs)
	{
		std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction, pblock_hash));
		czr::block_state pblock_state;
		auto pstate_error(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
		assert(!pstate_error);

		czr::witness_list_info parent_wl_info(ledger.block_witness_list(transaction, *pblock));
		if (parent_wl_info.is_compatible(wl_info))
		{
			if (best_pblock_hash.is_zero()
				|| (pblock_state.witnessed_level > best_pblock_state.witnessed_level)
				|| (pblock_state.witnessed_level == best_pblock_state.witnessed_level
					&& pblock_state.level < best_pblock_state.level)
				|| (pblock_state.witnessed_level == best_pblock_state.witnessed_level
					&& pblock_state.level == best_pblock_state.level
					&& pblock_hash < best_pblock_hash))
			{
				best_pblock_hash = pblock_hash;
				best_pblock_state = pblock_state;
			}
		}
	}

	return best_pblock_hash;
}

//witnessed level: search up along best parents, if meet majority of witnesses, the level is witnessed level
uint64_t czr::consensus::determine_witness_level(czr::block_hash const & best_parent_hash, czr::witness_list_info const & wl_info)
{
	czr::block_hash next_best_pblock_hash(best_parent_hash);
	std::vector<czr::account> collected_witness_list;
	uint64_t witnessed_level(0);
	while (true)
	{
		std::unique_ptr<czr::block> next_best_pblock(ledger.store.block_get(transaction, next_best_pblock_hash));
		czr::block_state next_best_pblock_state;
		bool bpstate_error(ledger.store.block_state_get(transaction, next_best_pblock_hash, next_best_pblock_state));
		assert(!bpstate_error);

		//genesis
		if (next_best_pblock_state.level == 0)
			break;

		auto account = next_best_pblock->hashables.from;
		if (wl_info.contains(account))
		{
			auto iter = std::find(collected_witness_list.begin(), collected_witness_list.end(), account);
			if (iter == collected_witness_list.end())
			{
				collected_witness_list.push_back(account);

				if (collected_witness_list.size() >= czr::majority_of_witnesses)
				{
					witnessed_level = next_best_pblock_state.level;
					break;
				}
			}
		}
		next_best_pblock_hash = next_best_pblock_state.best_parent;
	}

	return witnessed_level;
}

// the MC for this function is the MC built from this unit, not our current MC
bool czr::consensus::check_witness_list_mutations_along_mc(czr::block_hash const & best_parent_hash, czr::block const & block_a)
{
	czr::block_hash next_mc_hash(best_parent_hash);

	while (true)
	{
		std::unique_ptr<czr::block> mc_block(ledger.store.block_get(transaction, next_mc_hash));
		assert(mc_block != nullptr);

		// the parent has the same witness list and the parent has already passed the MC compatibility test
		if (!block_a.hashables.witness_list_block.is_zero() && block_a.hashables.witness_list_block == mc_block->hashables.witness_list_block)
			break;
		else
		{
			czr::witness_list_info wl_info (ledger.block_witness_list(transaction, block_a));
			czr::witness_list_info mc_wl_info(ledger.block_witness_list(transaction, *mc_block));
			if (!wl_info.is_compatible(mc_wl_info))
				return false;
		}

		if (mc_block->hash() == block_a.hashables.last_summary_block)
			break;

		czr::block_state mc_state;
		bool error(ledger.store.block_state_get(transaction, next_mc_hash, mc_state));
		assert(!error);

		if (mc_state.best_parent.is_zero())
		{
			auto msg(boost::str(boost::format("check_witness_list_mutations_along_mc, checked block: %1%, no best parent of block %2%") % block_a.hash().to_string() % next_mc_hash.to_string()));
			BOOST_LOG(node.log) << msg;
			throw std::runtime_error(msg);
		}

		next_mc_hash = mc_state.best_parent;
	}

	return true;
}

