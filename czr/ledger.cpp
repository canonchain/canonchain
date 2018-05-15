#include <czr/blockstore.hpp>
#include <czr/ledger.hpp>
#include <czr/node/common.hpp>
#include <czr/genesis.hpp>
#include <queue>
#include <unordered_set>


size_t czr::shared_ptr_block_hash::operator() (std::shared_ptr<czr::block> const & block_a) const
{
	auto hash(block_a->hash());
	auto result(static_cast<size_t> (hash.qwords[0]));
	return result;
}

bool czr::shared_ptr_block_hash::operator() (std::shared_ptr<czr::block> const & lhs, std::shared_ptr<czr::block> const & rhs) const
{
	return *lhs == *rhs;
}

czr::ledger::ledger(czr::block_store & store_a) :
	store(store_a)
{
}

// Balance for an account by account number
czr::uint128_t czr::ledger::account_balance(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::uint128_t result(0);
	czr::account_state acc_state;
	auto none(store.latest_account_state_get(transaction_a, account_a, acc_state));
	if (!none)
	{
		result = acc_state.balance.number();
	}
	return result;
}

bool czr::ledger::block_exists(czr::block_hash const & hash_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	auto result(store.block_exists(transaction, hash_a));
	return result;
}

// Return account containing hash
czr::account czr::ledger::block_account(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::account result;
	auto hash(hash_a);
	std::unique_ptr<czr::block> block(store.block_get(transaction_a, hash));
	result = block->hashables.from;
	assert(!result.is_zero());
	return result;
}

// Return latest block for account
czr::block_hash czr::ledger::latest(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::account_info info;
	auto latest_error(store.account_get(transaction_a, account_a, info));
	return latest_error ? 0 : info.head;
}

// Return latest root for account, account number of there are no blocks for this account.
czr::block_hash czr::ledger::latest_root(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::account_info info;
	auto latest_error(store.account_get(transaction_a, account_a, info));
	czr::block_hash result;
	if (latest_error)
	{
		result = account_a;
	}
	else
	{
		result = info.head;
	}
	return result;
}

void czr::ledger::dump_account_chain(czr::account const & account_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	auto hash(latest(transaction, account_a));
	while (!hash.is_zero())
	{
		auto block(store.block_get(transaction, hash));
		assert(block != nullptr);
		std::cerr << hash.to_string() << std::endl;
		hash = block->previous();
	}
}

void czr::ledger::change_account_latest(MDB_txn * transaction_a, czr::account const & account_a, czr::block_hash const & hash_a, uint64_t const & block_count_a)
{
	czr::account_info info;
	auto exists(!store.account_get(transaction_a, account_a, info));
	if (!exists)
	{
		assert(store.block_get(transaction_a, hash_a)->previous().is_zero());
		info.open_block = hash_a;
	}

	if (!hash_a.is_zero())
	{
		info.head = hash_a;
		info.modified = czr::seconds_since_epoch();
		info.block_count = block_count_a;
		store.account_put(transaction_a, account_a, info);
	}
	else
	{
		store.account_del(transaction_a, account_a);
	}
}

void czr::ledger::try_set_account_good_stable_mci(MDB_txn * transaction_a, czr::account const & account_a, uint64_t good_stable_mci)
{
	czr::account_info info;
	auto exists(!store.account_get(transaction_a, account_a, info));
	assert(exists);

	if (!info.first_good_stable_mci)
	{
		info.first_good_stable_mci = good_stable_mci;
		store.account_put(transaction_a, account_a, info);
	}
}

std::unique_ptr<czr::block> czr::ledger::successor(MDB_txn * transaction_a, czr::block_hash const & block_a)
{
	assert(store.account_exists(transaction_a, block_a) || store.block_exists(transaction_a, block_a));
	assert(store.account_exists(transaction_a, block_a) || latest(transaction_a, block_account(transaction_a, block_a)) != block_a);
	czr::block_hash successor;
	if (store.account_exists(transaction_a, block_a))
	{
		czr::account_info info;
		auto error(store.account_get(transaction_a, block_a, info));
		assert(!error);
		successor = info.open_block;
	}
	else
	{
		successor = store.block_successor(transaction_a, block_a);
	}
	assert(!successor.is_zero());
	auto result(store.block_get(transaction_a, successor));
	assert(result != nullptr);
	return result;
}

czr::witness_list_info czr::ledger::block_witness_list(MDB_txn * transaction_a, czr::block const & block_a)
{
	czr::witness_list_info wl_info;
	if (block_a.hashables.witness_list.empty())
	{
		auto wl_not_found(store.block_witness_list_get(transaction_a, block_a.hashables.witness_list_block, wl_info));
		assert(!wl_not_found);
	}
	else
	{
		wl_info = czr::witness_list_info(block_a.hashables.witness_list);
	}
	return wl_info;
}


//best parent:compatible parent, witnessed_level DESC, level ASC, unit ASC
czr::block_hash czr::ledger::determine_best_parent(MDB_txn * transaction_a, std::vector<czr::block_hash> const & pblock_hashs, czr::witness_list_info const & wl_info)
{
	czr::block_hash best_pblock_hash;
	czr::block_state best_pblock_state;
	for (czr::block_hash const & pblock_hash : pblock_hashs)
	{
		std::unique_ptr<czr::block> pblock(store.block_get(transaction_a, pblock_hash));
		czr::block_state pblock_state;
		auto pstate_error(store.block_state_get(transaction_a, pblock_hash, pblock_state));
		assert(!pstate_error);

		czr::witness_list_info parent_wl_info(block_witness_list(transaction_a, *pblock));
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
uint64_t czr::ledger::determine_witness_level(MDB_txn * transaction_a, czr::block_hash const & best_parent_hash, czr::witness_list_info const & wl_info)
{
	czr::block_hash next_best_pblock_hash(best_parent_hash);
	std::vector<czr::account> collected_witness_list;
	uint64_t witnessed_level(0);
	while (true)
	{
		//genesis
		if (next_best_pblock_hash == czr::genesis::block_hash)
			break;

		std::unique_ptr<czr::block> next_best_pblock(store.block_get(transaction_a, next_best_pblock_hash));
		czr::block_state next_best_pblock_state;
		bool bpstate_error(store.block_state_get(transaction_a, next_best_pblock_hash, next_best_pblock_state));
		assert(!bpstate_error);

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
bool czr::ledger::check_witness_list_mutations_along_mc(MDB_txn * transaction_a, czr::block_hash const & best_parent_hash, czr::block const & block_a)
{
	czr::block_hash next_mc_hash(best_parent_hash);

	while (true)
	{
		std::unique_ptr<czr::block> mc_block(store.block_get(transaction_a, next_mc_hash));
		assert(mc_block != nullptr);

		// the parent has the same witness list and the parent has already passed the MC compatibility test
		if (!block_a.hashables.witness_list_block.is_zero() && block_a.hashables.witness_list_block == mc_block->hashables.witness_list_block)
			break;
		else
		{
			czr::witness_list_info wl_info(block_witness_list(transaction_a, block_a));
			czr::witness_list_info mc_wl_info(block_witness_list(transaction_a, *mc_block));
			if (!wl_info.is_compatible(mc_wl_info))
				return false;
		}

		if (mc_block->hash() == block_a.hashables.last_summary_block)
			break;

		czr::block_state mc_state;
		bool error(store.block_state_get(transaction_a, next_mc_hash, mc_state));
		assert(!error);

		if (mc_state.best_parent.is_zero())
		{
			auto msg(boost::str(boost::format("check_witness_list_mutations_along_mc, checked block: %1%, no best parent of block %2%") % block_a.hash().to_string() % next_mc_hash.to_string()));
			throw std::runtime_error(msg);
		}

		next_mc_hash = mc_state.best_parent;
	}

	return true;
}

void czr::ledger::find_unstable_child_blocks(MDB_txn * transaction_a, czr::block_hash const & stable_hash, czr::block_hash & mc_child_hash, std::shared_ptr<std::vector<czr::block_hash>> branch_child_hashs)
{
	//get children ,filtered by children's best parent = check block's best parent
	czr::store_iterator child_iter(store.block_child_begin(transaction_a, czr::block_child_key(stable_hash, 0)));
	czr::store_iterator end(nullptr);
	while (true)
	{
		if (child_iter == end)
			break;
		czr::block_child_key key(child_iter->first);
		if (key.hash != stable_hash)
			break;

		czr::block_state child_state;
		bool error(store.block_state_get(transaction_a, key.child_hash, child_state));
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

uint64_t czr::ledger::find_mc_min_wl(MDB_txn * transaction_a, czr::block_hash const & best_block_hash, czr::witness_list_info const & witness_list)
{
	czr::block_state best_block_state;
	bool last_mc_block_state_error(store.block_state_get(transaction_a, best_block_hash, best_block_state));
	assert(!last_mc_block_state_error);

	//search up along main chain find min_wl
	uint64_t mc_end_level(best_block_state.witnessed_level);
	uint64_t min_wl(best_block_state.witnessed_level);
	czr::block_hash best_parent_block_hash(best_block_state.best_parent);
	while (true)
	{
		czr::block_state mc_block_state;
		bool mc_state_error(store.block_state_get(transaction_a, best_parent_block_hash, mc_block_state));
		assert(!mc_state_error);

		if (mc_block_state.level == 0 || mc_block_state.level < mc_end_level)
			break;

		std::unique_ptr<czr::block> mc_block(store.block_get(transaction_a, best_parent_block_hash));
		assert(mc_block != nullptr);

		if (witness_list.contains(mc_block->hashables.from)
			&& mc_block_state.witnessed_level < min_wl)
			min_wl = mc_block_state.witnessed_level;

		best_parent_block_hash = mc_block_state.best_parent;
	}

	return min_wl;
}

bool czr::ledger::check_stable_from_later(MDB_txn * transaction_a, czr::block_hash const & earlier_hash, std::vector<czr::block_hash> const & later_hashs)
{
	//genesis
	if (earlier_hash == czr::genesis::block_hash)
		return true;

	czr::block_state earlier_block_state;
	bool error(store.block_state_get(transaction_a, earlier_hash, earlier_block_state));
	assert(!error);

	if (earlier_block_state.is_free)
		return false;

	uint64_t max_later_parents_limci;
	czr::block_hash best_later_hash;
	czr::block_state best_later_state;
	for (czr::block_hash const & later_hash : later_hashs)
	{
		czr::block_state later_state;
		bool error(store.block_state_get(transaction_a, later_hash, later_state));
		assert(!error);

		//get max later limci 
		if (later_state.level > 0) //not genesis
		{
			assert(later_state.latest_included_mc_index);
			if (*later_state.latest_included_mc_index > max_later_parents_limci)
				max_later_parents_limci = *later_state.latest_included_mc_index;
		}

		//get best later hash
		if (best_later_hash.is_zero()
			|| (later_state.witnessed_level > best_later_state.witnessed_level)
			|| (later_state.witnessed_level == best_later_state.witnessed_level
				&& later_state.level < best_later_state.level)
			|| (later_state.witnessed_level == best_later_state.witnessed_level
				&& later_state.level == best_later_state.level
				&& later_hash < best_later_hash))
		{
			best_later_hash = later_hash;
			best_later_state = later_state;
		}
	}

	//get check block best parent's witness list
	czr::block_hash earlier_best_parent_hash(earlier_block_state.best_parent);
	std::unique_ptr<czr::block> earlier_best_parent_block = store.block_get(transaction_a, earlier_best_parent_hash);
	czr::witness_list_info earlier_wl_info(block_witness_list(transaction_a, *earlier_best_parent_block));

	//find min witness level
	uint64_t min_wl(find_mc_min_wl(transaction_a, best_later_hash, earlier_wl_info));

	//find unstable child blocks
	czr::block_hash mc_child_hash;
	std::shared_ptr<std::vector<czr::block_hash>> temp_branch_child_hashs(new std::vector<czr::block_hash>);
	find_unstable_child_blocks(transaction_a, earlier_best_parent_hash, mc_child_hash, temp_branch_child_hashs);

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
		bool state_error(store.block_state_get(transaction_a, mc_child_hash, mc_child_state));
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
			bool error(store.block_state_get(transaction_a, branch_child_hash, branch_child_state));
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
				bool error(store.block_state_get(transaction_a, hash, block_state));
				assert(!error);

				czr::store_iterator branch_child_iter(store.block_child_begin(transaction_a, czr::block_child_key(hash, 0)));
				while (true)
				{
					if (branch_child_iter == branch_child_iter_end)
						break;

					czr::block_child_key key(branch_child_iter->first);
					if (key.hash != hash)
						break;

					czr::block_state branch_child_state;
					bool branch_child_state_error(store.block_state_get(transaction_a, key.child_hash, branch_child_state));
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

