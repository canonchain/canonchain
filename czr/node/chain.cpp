
#include <czr/node/chain.hpp>
#include <czr/genesis.hpp>

czr::chain::chain(czr::node & node_a, std::function<void(std::shared_ptr<czr::block>)> block_stable_observer_a) :
	node(node_a),
	ledger(node_a.ledger),
	block_stable_observer(block_stable_observer_a)
{
}

czr::chain::~chain()
{
}

void czr::chain::save_block(MDB_txn * transaction_a, czr::block const & block_a)
{
	auto block_hash(block_a.hash());
	auto hashables(block_a.hashables);

	czr::witness_list_info wl_info(ledger.block_witness_list(transaction_a, block_a));

	uint64_t max_parent_level(0);
	for (czr::block_hash & pblock_hash : block_a.parents())
	{
		std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction_a, pblock_hash));
		czr::block_state pblock_state;
		auto pstate_error(ledger.store.block_state_get(transaction_a, pblock_hash, pblock_state));
		assert(!pstate_error);

		//remove parent blocks from free
		czr::free_key f_key(pblock_state.witnessed_level, pblock_state.level, pblock_hash);
		ledger.store.free_del(transaction_a, f_key);
		pblock_state.is_free = false;
		ledger.store.block_state_put(transaction_a, pblock_hash, pblock_state);

		//max parent level
		if (pblock_state.level > max_parent_level)
		{
			max_parent_level = pblock_state.level;
		}

		//save child
		ledger.store.block_child_put(transaction_a, czr::block_child_key(pblock_hash, block_hash));
	}

	czr::account_info info;
	auto account_exists(!ledger.store.account_get(transaction_a, block_a.hashables.from, info));

	//is_fork
	bool is_fork(account_exists && (block_a.previous().is_zero() || block_a.previous() != info.head));

	//best parent
	czr::block_hash best_pblock_hash(ledger.determine_best_parent(transaction_a, block_a.parents(), wl_info));

	//witnessed level
	uint64_t witnessed_level(ledger.determine_witness_level(transaction_a, best_pblock_hash, wl_info));

	//save block state
	czr::block_state state;
	state.is_fork = is_fork;
	state.is_free = true;
	state.best_parent = best_pblock_hash;
	state.level = max_parent_level + 1;
	state.witnessed_level = witnessed_level;
	ledger.store.block_state_put(transaction_a, block_hash, state);
	//save free
	ledger.store.free_put(transaction_a, czr::free_key(state.witnessed_level, state.level, block_hash));
	//save unstable
	ledger.store.unstable_put(transaction_a, block_hash);
	//save block
	ledger.store.block_put(transaction_a, block_hash, block_a);

	if (!state.is_fork)
	{
		ledger.change_account_latest(transaction_a, block_a.hashables.from, block_hash, info.block_count + 1);
	}
	else
	{
		if (!block_a.previous().is_zero())
		{
			czr::block_state previous_state;
			ledger.store.block_state_get(transaction_a, block_a.previous(), previous_state);
			if (previous_state.is_fork && !previous_state.is_stable)
			{
				czr::uint256_union fork_successor_hash;
				bool exists(!ledger.store.fork_successor_get(transaction_a, block_a.previous(), fork_successor_hash));
				if (!exists)
				{
					ledger.store.fork_successor_put(transaction_a, block_a.previous(), block_hash);
				}
			}
		}
	}

	update_main_chain(transaction_a, block_a);
}

void czr::chain::update_main_chain(MDB_txn * transaction_a, czr::block const & block_a)
{
	//search best free block by witnessed_level desc, level asc, block hash asc
	czr::store_iterator free_iter(ledger.store.free_begin(transaction_a));
	assert(free_iter != czr::store_iterator(nullptr));
	czr::free_key free_key(free_iter->first);
	czr::block_hash free_block_hash(free_key.hash_asc);

	if(free_block_hash == czr::genesis::block_hash) //genesis block
		return;

	czr::block_state free_block_state;
	ledger.store.block_state_get(transaction_a, free_block_hash, free_block_state);

	czr::block_hash last_best_pblock_hash(free_block_hash);
	czr::block_state last_best_pblock_state(free_block_state);

	std::unique_ptr<std::list<czr::block_hash>> new_mc_block_hashs(new std::list<czr::block_hash>);
	while (!last_best_pblock_state.is_on_main_chain)
	{
		new_mc_block_hashs->push_front(last_best_pblock_hash);

		//get pre best parent block
		last_best_pblock_hash = last_best_pblock_state.best_parent;
		bool pre_best_pblock_error(ledger.store.block_state_get(transaction_a, last_best_pblock_hash, last_best_pblock_state));
		assert(!pre_best_pblock_error);
	}
	assert(last_best_pblock_state.main_chain_index);

	uint64_t last_mci(*last_best_pblock_state.main_chain_index);

	//check stable mci not retreat
	uint64_t last_stable_mci = ledger.store.last_stable_mci_get(transaction_a);
	if (last_mci < last_stable_mci)
	{
		std::string msg(boost::str(boost::format("stable mci retreat, last added block: %1%, last mci: %2%, last stable mci: %3%") % block_a.hash().to_string() % last_mci % last_stable_mci));
		BOOST_LOG(node.log) << msg;
		throw std::runtime_error(msg);
	}

#pragma region delete old main chain block whose main chain index larger than last_mci

	//delete old main chian block
	for (czr::store_iterator i(ledger.store.main_chain_begin(transaction_a, last_mci + 1)), n(nullptr); i != n; ++i)
	{
		czr::block_hash old_mc_block_hash(i->second.uint256());
		uint64_t old_mci(i->first.uint64());
		ledger.store.main_chain_del(transaction_a, old_mci);
	}

	//clear old mci
	for (czr::store_iterator i(ledger.store.mci_block_rbeign(transaction_a)), n(nullptr); i != n; ++i)
	{
		czr::mci_block_key key(i->first);
		if (key.mci <= last_mci)
			break;

		czr::block_state old_mci_block_state;
		bool old_mci_block_error(ledger.store.block_state_get(transaction_a, key.hash, old_mci_block_state));
		assert(!old_mci_block_error && !old_mci_block_state.is_stable);

		old_mci_block_state.is_on_main_chain = false;
		old_mci_block_state.main_chain_index = boost::none;
		ledger.store.block_state_put(transaction_a, key.hash, old_mci_block_state);

		ledger.store.mci_block_del(transaction_a, czr::mci_block_key(key.mci, key.hash));
	}

#pragma endregion

#pragma region update main chain index

	uint64_t new_mci(last_mci);
	for (auto iter(new_mc_block_hashs->begin()); iter != new_mc_block_hashs->end(); iter++)
	{
		new_mci++;
		czr::block_hash new_mc_block_hash(*iter);
		czr::block_state new_mc_block_state;
		bool new_mc_block_state_error(ledger.store.block_state_get(transaction_a, new_mc_block_hash, new_mc_block_state));
		assert(!new_mc_block_state_error);

		new_mc_block_state.is_on_main_chain = true;
		new_mc_block_state.main_chain_index = new_mci;
		ledger.store.block_state_put(transaction_a, new_mc_block_hash, new_mc_block_state);
		ledger.store.main_chain_put(transaction_a, new_mci, new_mc_block_hash);
		ledger.store.mci_block_put(transaction_a, czr::mci_block_key(new_mci, new_mc_block_hash));

		std::shared_ptr<std::unordered_set<czr::block_hash>> updated_hashs(std::make_shared<std::unordered_set<czr::block_hash>>());
		update_parent_mci(transaction_a, new_mc_block_hash, new_mci, updated_hashs);
	}

#pragma endregion

#pragma region update latest included mc index

	//get from unstable blocks where main_chain_index > last_main_chain_index or main_chain_index == null
	std::unique_ptr<std::unordered_set<czr::block_hash>> to_update_limci_block_hashs(new std::unordered_set <czr::block_hash>);
	for (czr::store_iterator i(ledger.store.unstable_begin(transaction_a)), n(nullptr); i != n; ++i)
	{
		czr::block_hash block_hash(i->first.uint256());
		czr::block_state state;
		bool error(ledger.store.block_state_get(transaction_a, block_hash, state));
		assert(!error);
		if (!state.main_chain_index || (*state.main_chain_index) > last_mci)
			to_update_limci_block_hashs->insert(block_hash);
	}

	while (to_update_limci_block_hashs->size() > 0)
	{
		std::unique_ptr<std::list<czr::block_hash>> updated_limci_blocks(new std::list<czr::block_hash>);
		for (auto iter(to_update_limci_block_hashs->begin()); iter != to_update_limci_block_hashs->end(); iter++)
		{
			czr::block_hash block_hash(*iter);
			std::unique_ptr<czr::block> block = ledger.store.block_get(transaction_a, block_hash);
			assert(block != nullptr);

			bool is_parent_ready(true);
			boost::optional<uint64_t> max_limci;
			for (czr::block_hash & pblock_hash : block->parents())
			{
				czr::block_state pblock_state;
				bool pblock_state_error(ledger.store.block_state_get(transaction_a, pblock_hash, pblock_state));
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
			bool block_state_error(ledger.store.block_state_get(transaction_a, block_hash, block_state));
			assert(!block_state_error);
			block_state.latest_included_mc_index = max_limci;
			ledger.store.block_state_put(transaction_a, block_hash, block_state);

			updated_limci_blocks->push_back(block_hash);
		}

		for (auto iter(updated_limci_blocks->begin()); iter != updated_limci_blocks->end(); iter++)
			to_update_limci_block_hashs->erase(*iter);
	}

#pragma endregion

	check_mc_stable_block(transaction_a);
}

void czr::chain::check_mc_stable_block(MDB_txn * transaction_a)
{
	//get last stable main chain block
	uint64_t last_stable_mci(ledger.store.last_stable_mci_get(transaction_a));
	czr::block_hash last_stable_block_hash;
	bool mc_error(ledger.store.main_chain_get(transaction_a, last_stable_mci, last_stable_block_hash));
	assert(!mc_error);
	std::unique_ptr<czr::block> last_stable_block(ledger.store.block_get(transaction_a, last_stable_block_hash));
	assert(last_stable_block != nullptr);

	//get witness list of last stable block
	czr::witness_list_info last_stable_block_wl_info(ledger.block_witness_list(transaction_a, *last_stable_block));

	//get free main chain block (the lastest mc block)
	czr::store_iterator mc_iter(ledger.store.main_chain_rbegin(transaction_a));
	assert(mc_iter != czr::store_iterator(nullptr));
	czr::block_hash free_mc_block_hash(mc_iter->second.uint256());
	uint64_t min_wl(ledger.find_mc_min_wl(transaction_a, free_mc_block_hash, last_stable_block_wl_info));

	bool is_stable(false);

#pragma region check is stable

	czr::block_hash mc_child_hash(0);
	std::shared_ptr<std::list<czr::block_hash>> branch_child_hashs(new std::list<czr::block_hash>);
	ledger.find_unstable_child_blocks(transaction_a, last_stable_block_hash, mc_child_hash, branch_child_hashs);

	if (branch_child_hashs->size() == 0)
	{
		//non branch
		czr::block_state mc_child_state;
		bool state_error(ledger.store.block_state_get(transaction_a, mc_child_hash, mc_child_state));
		assert(!state_error);

		if (min_wl >= mc_child_state.level)
			is_stable = true;
	}
	else
	{
		//branch
		std::unique_ptr<std::list<czr::block_hash>> search_hash_list(new std::list<czr::block_hash>);
		uint64_t branch_max_level(0);
		for (auto i(branch_child_hashs->begin()); i != branch_child_hashs->end(); i++)
		{
			czr::block_hash branch_child_hash(*i);
			czr::block_state branch_child_state;
			bool error(ledger.store.block_state_get(transaction_a, branch_child_hash, branch_child_state));
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
			std::unique_ptr<std::list<czr::block_hash>> next_search_hash_list(new std::list<czr::block_hash>);

			for (auto iter(search_hash_list->begin()); iter != search_hash_list->end(); iter++)
			{
				czr::block_hash hash(*iter);
				czr::block_state block_state;
				bool error(ledger.store.block_state_get(transaction_a, hash, block_state));
				assert(!error);

				czr::store_iterator branch_child_iter(ledger.store.block_child_begin(transaction_a, czr::block_child_key(hash, 0)));
				while (true)
				{
					if (branch_child_iter == branch_child_iter_end)
						break;

					czr::block_child_key key(branch_child_iter->first);
					if (key.hash != hash)
						break;

					czr::block_state branch_child_state;
					bool branch_child_state_error(ledger.store.block_state_get(transaction_a, key.child_hash, branch_child_state));
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
	advance_mc_stable_block(transaction_a, mc_stable_hash, new_last_stable_mci);

	check_mc_stable_block(transaction_a);
}

void czr::chain::advance_mc_stable_block(MDB_txn * transaction_a, czr::block_hash const & mc_stable_hash, uint64_t const & mci)
{
	std::shared_ptr<std::set<czr::block_hash>> stable_block_hashs(new std::set<czr::block_hash>); //order by block hash
	search_stable_block(transaction_a, mc_stable_hash, mci, stable_block_hashs);

	std::unique_ptr<czr::block> mc_stable_block(ledger.store.block_get(transaction_a, mc_stable_hash));
	assert(mc_stable_block != nullptr);
	uint64_t mc_timestamp(mc_stable_block->hashables.exec_timestamp);

#pragma region handle fork block

	std::shared_ptr<std::unordered_set<czr::block_hash>> handle_fork_hashs(new std::unordered_set<czr::block_hash>);
	for (auto iter(stable_block_hashs->begin()); iter != stable_block_hashs->end(); iter++)
	{
		handle_fork_hashs->insert(*iter);
	}

	while (handle_fork_hashs->size() > 0)
	{
		std::unique_ptr<std::list<czr::block_hash>> handled_hashs(new std::list<czr::block_hash>);

		for (auto iter(handle_fork_hashs->begin()); iter != handle_fork_hashs->end(); iter++)
		{
			czr::block_hash stable_block_hash = *iter;
			std::unique_ptr<czr::block> stable_block = ledger.store.block_get(transaction_a, stable_block_hash);
			assert(stable_block != nullptr);

			czr::block_hash previous_hash(stable_block->previous());
			czr::block_state previous_state;
			if (!previous_hash.is_zero())
			{
				//previous not handled, handle previous first
				if (handle_fork_hashs->find(previous_hash) != handle_fork_hashs->end())
					continue;

				bool previous_state_error(ledger.store.block_state_get(transaction_a, previous_hash, previous_state));
				assert(!previous_state_error);
			}

			czr::block_state stable_block_state;
			bool block_state_error(ledger.store.block_state_get(transaction_a, stable_block_hash, stable_block_state));
			assert(!block_state_error);

			if (stable_block_state.is_fork && (previous_hash.is_zero() || !previous_state.is_fork))
			{
				std::unique_ptr<czr::block> successor(ledger.successor(transaction_a, stable_block->root()));
				czr::block_hash successor_hash(successor->hash());
				assert(successor != nullptr && successor_hash != stable_block_hash);
				czr::block_state successor_state;
				bool successor_state_error(ledger.store.block_state_get(transaction_a, successor_hash, successor_state));
				assert(!successor_state_error);

				if (!successor_state.main_chain_index
					|| *successor_state.main_chain_index > *stable_block_state.main_chain_index
					|| (*successor_state.main_chain_index == *stable_block_state.main_chain_index && successor_hash.number() > stable_block_hash.number()))
				{
					assert(!successor_state.is_fork);

					//rollbock account info
					rollback(transaction_a, successor_hash);

					//change successor
					change_successor(transaction_a, stable_block_hash);
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
		std::shared_ptr<std::list<czr::block_hash>> handled_stable_block_hashs(new std::list<czr::block_hash>);

		for (auto iter(stable_block_hashs->begin()); iter != stable_block_hashs->end(); iter++)
		{
			czr::block_hash block_hash = *iter;
			std::unique_ptr<czr::block> block(ledger.store.block_get(transaction_a, block_hash));
			assert(block != nullptr);

			//previous not handled, handle previous first
			czr::block_hash previous_hash(block->previous());
			if (!previous_hash.is_zero())
			{
				if (stable_block_hashs->find(previous_hash) != stable_block_hashs->end())
					continue;
			}

			czr::block_state block_state;
			bool block_state_error(ledger.store.block_state_get(transaction_a, block_hash, block_state));
			assert(!block_state_error);

			bool is_invalid;
			bool is_fail;
			if (!block_state.is_fork)
			{
				czr::account_state pre_from_state;
				bool exist(!ledger.store.latest_account_state_get(transaction_a, block->hashables.from, pre_from_state));
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
					ledger.store.account_state_put(transaction_a, block_state.from_state, from_state);
					ledger.store.latest_account_state_put(transaction_a, block->hashables.from, from_state);

					//try set account good stable mci
					ledger.try_set_account_good_stable_mci(transaction_a, block->hashables.from, mci);

					if (!is_fail)
					{
						//to account state
						czr::account_state pre_to_state;
						bool exist(!ledger.store.latest_account_state_get(transaction_a, block->hashables.to, pre_to_state));
						czr::uint128_t pre_to_balance(exist ? pre_to_state.balance.number() : 0);
						czr::uint128_t to_balance = pre_to_balance + amount;
						czr::account_state to_state(block->hashables.to, block_hash, pre_to_state.hash(), to_balance);
						block_state.to_state = to_state.hash();
						ledger.store.account_state_put(transaction_a, block_state.to_state, to_state);
						ledger.store.latest_account_state_put(transaction_a, block->hashables.to, to_state);
					}

					//save witness list
					if (block->hashables.witness_list.size() > 0)
					{
						czr::witness_list_info wl_info(block->hashables.witness_list);
						ledger.store.block_witness_list_put(transaction_a, block_hash, wl_info);

						czr::witness_list_key wl_key(wl_info.hash(), mci);
						if (!ledger.store.witness_list_hash_block_exists(transaction_a, wl_key))
						{
							//save witness list hash, mci -> block hash
							ledger.store.witness_list_hash_block_put(transaction_a, wl_key, block_hash);
						}
					}
				}
			}

			if (block_state.is_fork || is_invalid)
			{
				//todo:clear content;
			}

			//save block state
			block_state.is_invalid = is_invalid;
			block_state.is_fail = is_fail;
			block_state.mc_timestamp = mc_timestamp;
			block_state.is_stable = true;
			ledger.store.block_state_put(transaction_a, block_hash, block_state);

			//remove unstable
			ledger.store.unstable_del(transaction_a, block_hash);

#pragma region summary

			//parent summary hashs
			std::vector<czr::summary_hash> p_summary_hashs;
			for (czr::block_hash & pblock_hash : block->parents())
			{
				czr::summary_hash p_summary_hash;
				bool p_summary_hash_error(ledger.store.block_summary_get(transaction_a, pblock_hash, p_summary_hash));
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
					bool sl_block_hash_error(ledger.store.main_chain_get(transaction_a, mci, sl_block_hash));
					assert(!sl_block_hash_error);
					block_skiplist.push_back(sl_block_hash);

					czr::summary_hash sl_summary_hash;
					bool sl_summary_hash_error(ledger.store.block_summary_get(transaction_a, sl_block_hash, sl_summary_hash));
					assert(!sl_summary_hash_error);
					summary_skiplist.insert(sl_summary_hash);
				}
			}
			ledger.store.skiplist_put(transaction_a, block_hash, czr::skiplist_info(block_skiplist));

			//summary hash
			czr::summary_hash summary_hash = czr::summary::gen_summary_hash(block_hash, p_summary_hashs, summary_skiplist,
				block_state.is_fork, block_state.is_invalid, block_state.is_fail, block_state.from_state, block_state.to_state);
			ledger.store.block_summary_put(transaction_a, block_hash, summary_hash);
			ledger.store.summary_block_put(transaction_a, summary_hash, block_hash);

#pragma endregion

			//todo:delete summary_hash from hash_tree_summary

			block_stable_observer(std::move(block));

			handled_stable_block_hashs->push_back(block_hash);
		}

		for (auto iter(handled_stable_block_hashs->begin()); iter != handled_stable_block_hashs->end(); iter++)
		{
			stable_block_hashs->erase(*iter);
		}
	}

#pragma endregion

	//update last stable main chain index
	ledger.store.last_stable_mci_put(transaction_a, mci);
}

//Rollback blocks until `block_hash' is not fork
void czr::chain::rollback(MDB_txn * transaction_a, czr::block_hash const & block_hash)
{
	assert(ledger.store.block_exists(transaction_a, block_hash));

	auto account_l(ledger.block_account(transaction_a, block_hash));
	czr::block_state state;
	bool state_error(ledger.store.block_state_get(transaction_a, block_hash, state));
	assert(!state_error);
	if (state.is_fork)
		return;

	while (true)
	{
		czr::account_info info;
		auto latest_error(ledger.store.account_get(transaction_a, account_l, info));
		assert(!latest_error);

		czr::block_hash latest_hash(info.head);
		auto latest_block(ledger.store.block_get(transaction_a, latest_hash));

		ledger.change_account_latest(transaction_a, account_l, latest_block->previous(), info.block_count - 1);

		if (!latest_block->previous().is_zero())
			ledger.store.block_successor_clear(transaction_a, latest_block->previous());

		czr::block_state latest_state;
		bool state_error(ledger.store.block_state_get(transaction_a, latest_hash, latest_state));
		assert(!state_error);
		latest_state.is_fork = true;
		ledger.store.block_state_put(transaction_a, latest_hash, latest_state);

		if (latest_hash == block_hash)
			break;
	}
}

void czr::chain::change_successor(MDB_txn * transaction_a, czr::block_hash const & block_hash)
{
	czr::block_hash new_successor_hash(block_hash);
	std::unique_ptr<czr::block> new_successor;
	czr::block_state new_successor_state;

	while (true)
	{
		new_successor = ledger.store.block_get(transaction_a, new_successor_hash);
		assert(new_successor != nullptr);
		bool new_successor_state_error(ledger.store.block_state_get(transaction_a, new_successor_hash, new_successor_state));
		assert(!new_successor_state_error);

		//update account info
		czr::account_info info;
		ledger.store.account_get(transaction_a, new_successor->hashables.from, info);
		ledger.change_account_latest(transaction_a, new_successor->hashables.from, new_successor_hash, info.block_count + 1);

		//set predecessor
		ledger.store.block_predecessor_set(transaction_a, *new_successor, true);

		//update state is_fork
		new_successor_state.is_fork = false;
		ledger.store.block_state_put(transaction_a, new_successor_hash, new_successor_state);

		//get next fork successor
		czr::block_hash fork_successor_hash;
		bool exists(!ledger.store.fork_successor_get(transaction_a, new_successor_hash, fork_successor_hash));
		if (!exists)
			break;
		ledger.store.fork_successor_del(transaction_a, new_successor_hash);

		new_successor_hash = fork_successor_hash;
	}
}

void czr::chain::update_parent_mci(MDB_txn * transaction_a, czr::block_hash const & hash_a, uint64_t const & mci, std::shared_ptr<std::unordered_set<czr::block_hash>> updated_hashs)
{
	std::unique_ptr<czr::block> block = ledger.store.block_get(transaction_a, hash_a);
	assert(block != nullptr);
	for (auto const & pblock_hash : block->parents())
	{
		if (updated_hashs->find(pblock_hash) != updated_hashs->end())
			continue;

		czr::block_state pblock_state;
		bool pblock_state_error(ledger.store.block_state_get(transaction_a, pblock_hash, pblock_state));
		assert(!pblock_state_error);
		if (pblock_state.main_chain_index && *pblock_state.main_chain_index < mci)
			continue;

		pblock_state.main_chain_index = mci;
		ledger.store.block_state_put(transaction_a, pblock_hash, pblock_state);
		ledger.store.mci_block_put(transaction_a, czr::mci_block_key(mci, pblock_hash));

		updated_hashs->insert(pblock_hash);

		update_parent_mci(transaction_a, pblock_hash, mci, updated_hashs);
	}
}

void czr::chain::search_stable_block(MDB_txn * transaction_a, czr::block_hash const & block_hash, uint64_t const & mci, std::shared_ptr<std::set<czr::block_hash>> stable_block_hashs)
{
	//has updated
	if (stable_block_hashs->find(block_hash) != stable_block_hashs->end())
		return;

	czr::block_state state;
	bool state_error(ledger.store.block_state_get(transaction_a, block_hash, state));
	assert(!state_error);

	if (state.level == 0)
		return;
	assert(state.main_chain_index);
	if (*state.main_chain_index != mci)
		return;

	stable_block_hashs->insert(block_hash);

	std::unique_ptr<czr::block> block(ledger.store.block_get(transaction_a, block_hash));
	for (czr::block_hash & pblock_hash : block->parents())
	{
		search_stable_block(transaction_a, pblock_hash, mci, stable_block_hashs);
	}
}

std::vector<uint64_t> czr::chain::cal_skip_list_mcis(uint64_t const & mci)
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


