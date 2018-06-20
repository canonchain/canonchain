
#include <czr/node/validation.hpp>
#include <czr/genesis.hpp>

czr::validation::validation(czr::node & node_a) :
	node(node_a),
	ledger(node_a.ledger),
	graph(ledger.store)
{
}

czr::validation::~validation()
{
}

czr::validate_result czr::validation::validate(MDB_txn * transaction_a, czr::joint_message const & message)
{
	czr::validate_result result;
	if (message.block == nullptr)
	{
		result.code = czr::validate_result_codes::invalid_message;
		result.err_msg = "block is null";
		return result;
	}

	std::shared_ptr<czr::block> block(message.block);
	auto hash(block->hash());

	//check if block is in invalid block cache;
	if (node.invalid_block_cache.contains(hash))
	{
		result.code = czr::validate_result_codes::known_invalid_block;
		return result;
	}

	//check timestamp
	if (czr::seconds_since_epoch() < block->hashables.exec_timestamp)
	{
		result.code = czr::validate_result_codes::exec_timestamp_too_late;
		return result;
	}

	//data size
	if (block->hashables.data.size() > czr::max_data_size)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = "data size too large";
		return result;
	}

	if (validate_message(block->hashables.from, hash, block->signature))
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = "invalid signature";
		return result;
	}

	auto exists(ledger.store.block_exists(transaction_a, hash));
	if (exists)
	{
		result.code = czr::validate_result_codes::old;
		return result;
	}

#pragma region validate hash_tree_summary
	if (!message.summary_hash.is_zero())
	{
		//todo:check if summary_hash exists in hash_tree_summary
		bool hash_tree_summary_exists;
		if (!exists)
		{
			result.code = czr::validate_result_codes::missing_hash_tree_summary;
			return result;
		}

		//get parent summary hashs
		std::vector<czr::summary_hash> p_summary_hashs;
		for (czr::block_hash & pblock_hash : block->parents())
		{
			czr::summary_hash p_summary_hash;
			bool exists;	//todo:get p_summary_hash from hash_tree_summary
			if (!exists)
			{
				exists = !ledger.store.block_summary_get(transaction_a, pblock_hash, p_summary_hash);
			}

			if (!exists)
			{
				result.code = czr::validate_result_codes::invalid_message;
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
					exists = !ledger.store.block_summary_get(transaction_a, sl_block_hash, sl_summary_hash);
				}

				if (!exists)
				{
					result.code = czr::validate_result_codes::invalid_message;
					result.err_msg = boost::str(boost::format("Skiplist block %1% 's summary not found") % sl_block_hash.to_string());
					return result;
				}

				summary_skiplist.insert(sl_summary_hash);
			}
		}

		czr::summary_hash calc_summary_hash = czr::summary::gen_summary_hash(hash, p_summary_hashs, summary_skiplist,
			message.is_fork, message.is_invalid, message.is_fail, message.from_state, message.to_state);

		if (message.summary_hash != calc_summary_hash)
		{
			result.code = czr::validate_result_codes::invalid_message;
			result.err_msg = boost::str(boost::format("Invalid message summaryhash: %1%, calculated summary hash: %2%") % message.summary_hash.to_string() % calc_summary_hash.to_string());
			return result;
		}
	}

#pragma endregion

#pragma region validate parents and previous

	//check parents size
	size_t parents_size(block->parents().size());
	if (parents_size == 0 || parents_size > czr::max_parents_size)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("Invalid parents size: %1%") % parents_size);
		return result;
	}

	//check missing parents and previous
	for (czr::block_hash & pblock_hash : block->parents_and_previous())
	{
		if (!ledger.store.block_exists(transaction_a, pblock_hash))
		{
			result.missing_parents_and_previous.push_back(pblock_hash);
			continue;
		}
	}
	if (result.missing_parents_and_previous.size() > 0)
	{
		//todo:check any of missing parents and previous is known invalid block, if so return invalid block;

		result.code = czr::validate_result_codes::missing_parents_and_previous;
		return result;
	}

	//check exe_timestamp
	for (czr::block_hash pblock_hash : block->parents_and_previous())
	{
		//check parent exe_timestamp
		std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction_a, pblock_hash));
		if (pblock->hashables.exec_timestamp > block->hashables.exec_timestamp)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("Invalid exec_timestamp, parent or previous: %1%") % pblock_hash.to_string());
			return result;
		}
	}

	//check pervious
	if (!block->previous().is_zero())
	{
		std::unique_ptr<czr::block> previous_block = ledger.store.block_get(transaction_a, block->previous());
		assert(previous_block != nullptr);
		
		//check pervious from
		if (previous_block->hashables.from != block->hashables.from)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("block from %1% not equal to pervious from %2%") % block->hashables.from.to_account() % previous_block->hashables.from.to_account());
			return result;
		}

		//previous must be included by or equal to parents
		bool is_included(graph.determine_if_included_or_equal(transaction_a, block->previous(), block->parents()));
		if (!is_included)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("pervious %1% not included by parents") % block->previous().to_string());
			return result;
		}
	}

	//check parents
	czr::block_hash pre_pblock_hash;
	std::list<czr::block_hash> pre_pblock_hashs;
	for (czr::block_hash & pblock_hash : block->parents())
	{
		//check order
		if (pblock_hash <= pre_pblock_hash)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = "parent hash not ordered";
			return result;
		}
		pre_pblock_hash = pblock_hash;

		//check if related
		for (czr::block_hash const & pre_hash : pre_pblock_hashs)
		{
			czr::graph_compare_result graph_result(graph.compare(transaction_a, pblock_hash, pre_hash));
			if (graph_result != czr::graph_compare_result::non_related)
			{
				result.code = czr::validate_result_codes::invalid_block;
				result.err_msg = boost::str(boost::format("parent %1% are related to parent %2%") % pblock_hash.to_string() % pre_hash.to_string());
				return result;
			}
		}
		pre_pblock_hashs.push_back(pblock_hash);
	}

#pragma endregion

#pragma region check last summary

	czr::block_hash last_summary_block_hash(block->hashables.last_summary_block);
	czr::block_state last_summary_block_state;
	bool last_summary_block_exists(!ledger.store.block_state_get(transaction_a, block->hashables.last_summary_block, last_summary_block_state));
	if (!last_summary_block_exists)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% not exists") % block->hashables.last_summary_block.to_string());
		return result;
	}

	if (!last_summary_block_state.is_on_main_chain)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not on main chain") % block->hashables.last_summary_block.to_string());
		return result;
	}

	assert(last_summary_block_state.main_chain_index);
	uint64_t last_summary_mci = *last_summary_block_state.main_chain_index;

	uint64_t max_parent_limci;
	for (czr::block_hash & pblock_hash : block->parents())
	{
		if (pblock_hash != czr::genesis::block_hash)
		{
			czr::block_state pblock_state;
			bool error(ledger.store.block_state_get(transaction_a, pblock_hash, pblock_state));
			assert(!error);
			assert(pblock_state.latest_included_mc_index);
			if (*pblock_state.latest_included_mc_index > max_parent_limci)
				max_parent_limci = *pblock_state.latest_included_mc_index;
		}
	}

	if (last_summary_mci > max_parent_limci)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not included in parents") % block->hashables.last_summary_block.to_string());
		return result;
	}

#pragma endregion

#pragma region validate skiplist
	if (message.block_skiplist.size() > 0)
	{
		czr::block_hash prev_sl_block_hash;
		for (czr::block_hash const & sl_block_hash : message.block_skiplist)
		{
			if (sl_block_hash <= prev_sl_block_hash)
			{
				result.code = czr::validate_result_codes::invalid_message;
				result.err_msg = "skiplist block hashs not ordered";
				return result;
			}
			prev_sl_block_hash = sl_block_hash;

			czr::block_state sl_block_state;
			bool sl_block_state_exists(!ledger.store.block_state_get(transaction_a, sl_block_hash, sl_block_state));
			if (!sl_block_state_exists)
			{
				result.code = czr::validate_result_codes::invalid_message;
				result.err_msg = boost::str(boost::format("skiplist block %1% not found") % sl_block_hash.to_string());
				return result;
			}

			// if not stable, can't check that it is on MC as MC is not stable in its area yet
			if (sl_block_state.is_stable)
			{
				if (!sl_block_state.is_on_main_chain)
				{
					result.code = czr::validate_result_codes::invalid_message;
					result.err_msg = boost::str(boost::format("skiplist block %1% is not on main chain") % sl_block_hash.to_string());
					return result;
				}

				assert(sl_block_state.main_chain_index);
				if (*sl_block_state.main_chain_index % czr::skiplist_divisor != 0)
				{
					result.code = czr::validate_result_codes::invalid_message;
					result.err_msg = boost::str(boost::format("skiplist block %1% MCI is not divisible by %2%") % sl_block_hash.to_string() % czr::skiplist_divisor);
					return result;
				}
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
		bool wl_block_state_exists(!ledger.store.block_state_get(transaction_a, block->hashables.witness_list_block, wl_block_state));
		if (!wl_block_state_exists)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% not found") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block is stable
		if (!wl_block_state.is_stable)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% is not stable") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block is fork or invalid
		if (wl_block_state.is_fork || wl_block_state.is_invalid)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% is fork or invalid") % block->hashables.witness_list_block.to_string());
			return result;
		}

		//check if wl block come before last summary
		assert(wl_block_state.main_chain_index);
		if (*wl_block_state.main_chain_index > last_summary_mci)
		{
			result.code = czr::validate_result_codes::invalid_block;
			result.err_msg = boost::str(boost::format("witness_list_block %1% must come before last summary") % block->hashables.witness_list_block.to_string());
			return result;
		}

		bool wl_info_exists(!ledger.store.block_witness_list_get(transaction_a, block->hashables.witness_list_block, wl_info));
		if (!wl_info_exists)
		{
			result.code = czr::validate_result_codes::invalid_block;
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
				result.code = czr::validate_result_codes::invalid_block;
				result.err_msg = "witness_list not ordered or duplicates";
				return result;
			}
			prev_witness = curr_witness;
		}

		//check that all witnesses are already known and their blocks are good and stable
		for (czr::account & witness : block->hashables.witness_list)
		{
			czr::account_info info;
			bool exists(!ledger.store.account_get(transaction_a, witness, info));
			if (!exists || !info.first_good_stable_mci || *info.first_good_stable_mci > last_summary_mci)
			{
				result.code = czr::validate_result_codes::invalid_block;
				result.err_msg = boost::str(boost::format("witnesses %1% are not stable, not good, or don't come before last summary") % witness.to_string());
				return result;
			}
		}

		wl_info = witness_list_info(block->hashables.witness_list);
	}
	else
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = "no witnesses or not enough witnesses";
		return result;
	}

	//check best parent
	czr::block_hash best_pblock_hash(ledger.determine_best_parent(transaction_a, block->parents(), wl_info));
	if (best_pblock_hash.is_zero())
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = "no compatible best parent";
		return result;
	}

	//check witness list mutations along mc
	bool is_mutations_ok(ledger.check_witness_list_mutations_along_mc(transaction_a, best_pblock_hash, *block));
	if (!is_mutations_ok)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = "too many witness list mutations along mc";
		return result;
	}

	//check witnessed level did not retreat
	uint64_t witnessed_level(ledger.determine_witness_level(transaction_a, best_pblock_hash, wl_info));
	czr::block_state best_pblock_state;
	bool best_pblock_state_error(ledger.store.block_state_get(transaction_a, best_pblock_hash, best_pblock_state));
	assert(!best_pblock_state_error);
	if (witnessed_level < best_pblock_state.witnessed_level)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("witnessed level retreats from &1& to &2&") % best_pblock_state.witnessed_level % witnessed_level);
		return result;
	}

#pragma endregion

#pragma region  check if last summary block is stable in view of parents and mci not retreat

	bool is_last_summary_stable = ledger.check_stable_from_later_blocks(transaction_a, last_summary_block_hash, block->parents());
	if (!is_last_summary_stable)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary block %1% is not stable in view of parent") % block->hashables.last_summary_block.to_string());
		return result;
	}

	if (!last_summary_block_state.is_stable)
	{
		node.chain->advance_mc_stable_block(transaction_a ,last_summary_block_hash, last_summary_mci);
	}

	//check last summary hash
	czr::summary_hash last_summary_hash;
	bool last_summary_exists(!ledger.store.block_summary_get(transaction_a, last_summary_block_hash, last_summary_hash));
	if (!last_summary_exists)
	{
		auto msg(boost::str(boost::format("last summary block %1% is stable but summary not found") % last_summary_block_hash.to_string()));
		BOOST_LOG(node.log) << msg;
		throw std::runtime_error(msg);
	}
	if (last_summary_hash != block->hashables.last_summary)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary %1% and last summary block %2% do not match") % block->hashables.last_summary.to_string() % block->hashables.last_summary_block.to_string());
		return result;
	}

	//check last summary mci retreat
	uint64_t max_parent_last_summary_mci;
	for (czr::block_hash & pblock_hash : block->parents())
	{
		std::unique_ptr<czr::block> pblock = ledger.store.block_get(transaction_a, pblock_hash);
		assert(pblock != nullptr);

		if (block->hashables.last_summary_block != czr::genesis::block_hash) //not genesis
		{
			czr::block_state parent_last_summary_state;
			bool error(ledger.store.block_state_get(transaction_a, pblock->hashables.last_summary_block, parent_last_summary_state));
			assert(!error);
			assert(parent_last_summary_state.main_chain_index);
			if (*parent_last_summary_state.main_chain_index > max_parent_last_summary_mci)
				max_parent_last_summary_mci = *parent_last_summary_state.main_chain_index;
		}
	}
	if (last_summary_mci < max_parent_last_summary_mci)
	{
		result.code = czr::validate_result_codes::invalid_block;
		result.err_msg = boost::str(boost::format("last summary mci %1% retreat, max parent last summary mci %2%") % last_summary_mci % max_parent_last_summary_mci);
		return result;
	}

#pragma endregion
	
	result.code = czr::validate_result_codes::ok;
	result.account = block->hashables.from;
	result.amount = block->hashables.amount.number();
}



