#include <czr/blockstore.hpp>
#include <czr/ledger.hpp>
#include <czr/node/common.hpp>

namespace
{
	/**
	* Roll back the visited block
	*/
	class rollback_visitor : public czr::block_visitor
	{
	public:
		rollback_visitor(MDB_txn * transaction_a, czr::ledger & ledger_a) :
			transaction(transaction_a),
			ledger(ledger_a)
		{
		}
		virtual ~rollback_visitor() = default;
		void block(czr::block const & block_a) override
		{
			auto hash(block_a.hash());
			auto balance(ledger.block_balance(transaction, block_a.hashables.previous));

			czr::account_info info;
			auto error(ledger.store.account_get(transaction, block_a.hashables.account, info));
			assert(!error);
			ledger.change_latest(transaction, block_a.hashables.account, block_a.hashables.previous, balance, info.block_count - 1);

			auto previous(ledger.store.block_get(transaction, block_a.hashables.previous));
			if (previous != nullptr)
				ledger.store.block_successor_clear(transaction, block_a.hashables.previous);
			ledger.store.block_del(transaction, hash);
		}
		MDB_txn * transaction;
		czr::ledger & ledger;
	};

	class ledger_processor : public czr::block_visitor
	{
	public:
		ledger_processor(czr::ledger &, MDB_txn *);
		virtual ~ledger_processor() = default;
		void block(czr::block const &) override;
		czr::ledger & ledger;
		MDB_txn * transaction;
		czr::process_return result;
	private:
		void validate_block(czr::block const &);
		void save_block(czr::block const &);
		void update_main_chain(czr::block const &);
		void advance_stable_mc_block(czr::block const &);
	};

	void ledger_processor::block(czr::block const & block_a)
	{
		validate_block(block_a);
		if (result.code == czr::process_result::progress)
			save_block(block_a);
	}

	//todo:validate block/////////////
	void ledger_processor::validate_block(czr::block const & block_a)
	{
		auto hash(block_a.hash());
		auto existing(ledger.store.block_exists(transaction, hash));
		if (existing)
		{
			result.code = czr::process_result::old;
			return;
		}

		if (validate_message(block_a.hashables.account, hash, block_a.signature))
		{
			result.code = czr::process_result::bad_signature;
			return;
		}

		if (block_a.hashables.account.is_zero())
		{
			result.code = czr::process_result::opened_burn_account;
			return;
		}

		bool is_fork(false);
		czr::account_info info;
		auto account_not_found(ledger.store.account_get(transaction, block_a.hashables.account, info));
		if (!account_not_found)
		{
			// Account already exists
			if (block_a.hashables.previous.is_zero())
			{
				//todo:store in fork block
				is_fork = true;
			}
			else
			{
				if (!ledger.store.block_exists(transaction, block_a.hashables.previous))
				{
					result.code = czr::process_result::gap_previous;
					return;
				}

				if (block_a.hashables.previous != info.head)
				{
					//todo:store in fork block
					is_fork = true;
				}
			}
		}
		else
		{
			// Account does not yet exists
			if (!block_a.previous().is_zero())
			{
				result.code = czr::process_result::gap_previous;
				return;
			}

			if (block_a.hashables.link.is_zero())
			{
				result.code = czr::process_result::gap_source;
				return;
			}
		}

		czr::amount previous_balance(0);
		if (!block_a.hashables.previous.is_zero()) //not first block
		{
			if (!is_fork)
				previous_balance = info.balance;
			else
			{
				auto previous(ledger.store.block_get(transaction, block_a.hashables.previous));
				czr::block * block = dynamic_cast<czr::block *>(&(*previous));
				previous_balance = block->hashables.balance;
			}
		}

		result.amount = block_a.hashables.balance.number() - previous_balance.number();
		bool is_send(block_a.hashables.balance < previous_balance);
		if (!is_send)
		{
			if (!block_a.hashables.link.is_zero())
			{
				if (!ledger.store.block_exists(transaction, block_a.hashables.link))
				{
					result.code = czr::process_result::gap_source;
					return;
				}

				czr::pending_key key(block_a.hashables.account, block_a.hashables.link);
				czr::pending_info pending;
				if (ledger.store.pending_get(transaction, key, pending))
				{
					result.code = czr::process_result::unreceivable;
					return;
				}

				if (result.amount != pending.amount)
				{
					result.code = czr::process_result::balance_mismatch;
					return;
				}
			}
			else
			{
				// If there's no link, the balance must remain the same
				if (!result.amount.is_zero())
				{
					result.code = czr::process_result::balance_mismatch;
					return;
				}
			}
		}

		result.code = czr::process_result::progress;
		result.is_fork = is_fork;
		result.is_send = is_send;
		result.block_count = info.block_count;
		result.account = block_a.hashables.account;
	}

	void ledger_processor::save_block(czr::block const & block_a)
	{
		//todo:if genesis block return/////////////////

		auto block_hash(block_a.hash());
		auto hashables(block_a.hashables);

		czr::witness_list_info wl_info;
		if (hashables.witness_list.empty())
		{
			auto wl_not_found(ledger.store.block_witnesslist_get(transaction, hashables.witness_list_block, wl_info));
			assert(!wl_not_found);
		}
		else
		{
			wl_info = czr::witness_list_info(hashables.witness_list);

			auto wl_hash(wl_info.hash());
			if (!ledger.store.witnesslisthash_block_exists(transaction, wl_hash))
			{
				//save witness list hash -> block hashparent_hash
				ledger.store.witnesslisthash_block_put(transaction, wl_hash, block_hash);
			}
			//save block hash -> witness list info
			ledger.store.block_witnesslist_put(transaction, block_hash, wl_info);
		}

		std::unique_ptr<czr::block> best_pblock;
		czr::block_hash best_pblock_hash;
		czr::block_state best_pblock_state;
		uint32_t max_parent_level;
		uint32_t witnessed_level;
		for each (czr::block_hash pblock_hash in hashables.parents)
		{
			//remove parent blocks from free
			ledger.store.free_del(transaction, pblock_hash);

			std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction, pblock_hash));
			czr::block_state pblock_state;
			auto pstate_not_found(ledger.store.block_state_get(transaction, pblock_hash, pblock_state));
			assert(!pstate_not_found);

			if (pblock_state.level > max_parent_level)
			{
				max_parent_level = pblock_state.level;
			}

			czr::witness_list_info parent_wl_info;
			if (pblock->hashables.witness_list.empty())
			{
				auto pwl_not_found(ledger.store.block_witnesslist_get(transaction, pblock->hashables.witness_list_block, parent_wl_info));
				assert(!pwl_not_found);
			}
			else
			{
				parent_wl_info = czr::witness_list_info(pblock->hashables.witness_list);
			}

			//best parent:compatible parent, witnessed_level DESC, level ASC, unit ASC
			if (parent_wl_info.is_compatible(wl_info))
			{
				if (best_pblock == nullptr
					|| (pblock_state.witnessed_level > best_pblock_state.witnessed_level)
					|| (pblock_state.witnessed_level == best_pblock_state.witnessed_level
						&& pblock_state.level < best_pblock_state.level)
					|| (pblock_state.witnessed_level == best_pblock_state.witnessed_level
						&& pblock_state.level == best_pblock_state.level
						&& pblock_hash < best_pblock_hash))
				{
					best_pblock = std::move(pblock);
					best_pblock_hash = pblock_hash;
					best_pblock_state = pblock_state;
				}
			}
		}
		assert(best_pblock != nullptr);

		//witnessed level: search up along best parents, if meet majority of witnesses, the level is witnessed level
		std::unique_ptr<czr::block> pre_best_pblock(std::move(best_pblock));
		czr::block_state pre_best_pblock_state;
		std::vector<czr::account> collected_witness_list;
		while (true)
		{
			//genesis
			if (pre_best_pblock_state.level == 0)
				break;

			auto account = pre_best_pblock->hashables.account;
			if (wl_info.contains(account))
			{
				auto iter = std::find(collected_witness_list.begin(), collected_witness_list.end(), account);
				if (iter == collected_witness_list.end())
				{
					collected_witness_list.push_back(account);

					if (collected_witness_list.size() >= czr::majority_of_witnesses)
						break;
				}
			}
			pre_best_pblock = ledger.store.block_get(transaction, pre_best_pblock_state.best_parent);
			auto bpstate_not_found(ledger.store.block_state_get(transaction, pre_best_pblock_state.best_parent, pre_best_pblock_state));
			assert(!bpstate_not_found);
		}

		//save block state
		czr::block_state state;
		state.is_fork = result.is_fork;
		state.best_parent = best_pblock_hash;
		state.level = max_parent_level + 1;
		state.witnessed_level = pre_best_pblock_state.level;
		state.creation_date = std::chrono::system_clock::now();
		ledger.store.block_state_put(transaction, block_hash, state);
		//save free
		czr::free_block free(state.witnessed_level, state.level);
		ledger.store.free_put(transaction, block_hash, free);
		//save block
		ledger.store.block_put(transaction, block_hash, block_a);

		if (!result.is_fork)
		{
			ledger.change_latest(transaction, block_a.hashables.account, block_hash, block_a.hashables.balance, result.block_count + 1);
		}

		update_main_chain(block_a);
	}

	void ledger_processor::update_main_chain(czr::block const & block_a)
	{
		//if genesis return;

		//search best free block by witnessed_level desc, level asc, block hash asc

		//get best_parent of best free block, check best parent must be unstable

		//auto new_mc_blocks
		//if best_parent is_on_main_chain == false 
		//	set is_on_main_chain = true , main_chain_index = null
		//	auto pre_best_parent(best_parent.best_parent);
		//  new_mc_blocks.push_back(pre_best_parent)
		//  while (pre_best_parent is_on_main_chain == false )
		//		set is_on_main_chain = true , main_chain_index = null
		//		new_mc_blocks.push_back(pre_best_parent)
		//		pre_best_parent = pre_best_parent.best_parent

		//  auto last_main_chain_index = pre_best_parent.main_chain_index

		//--update main chain index
		//	check: there is no block is_on_main_chain = true and is_stable = true and main_chain_index > last_main_chain_index and main_chain_index != null
		//  SET is_on_main_chain=0, main_chain_index=NULL WHERE main_chain_index > last_main_chain_index and main_chain_index != null
		//	auto main_chain_index = last_main_chain_index;
		//	new_mc_blocks order by level
		//  for(auto mc_block : new_mc_blocks)
		//		main_chain_index++;
		//		search up along mc_block'parents whose main_chain_index==null and set main_chain_index=main_chain_index

		//--update latest included mc index
		//auto to_update_limci_blocks //get from unstable blocks where main_chain_index > last_main_chain_index or main_chain_index == null
		//while(to_update_limci_blocks.length > 0)
		//	list<block> updated_limci_blocks;
		//	for (auto to_update_block :to_update_limci_blocks)
		//		if(to_update_block.parents.exists(!p.is_on_main_chain && p.latest_included_mc_index == null))
		//			continue;
		//		auto max_limci = -1;
		//		for (auto p : to_update_block.parents)
		//			if(p.is_on_main_chain)
		//				if(max_limci < p.main_chain_index)
		//					max_limci = p.main_chain_index;
		//			else 
		//				if(max_limci < p.latest_included_mc_index)
		//					max_limci = p.latest_included_mc_index;
		//		assert(max_limci > 0);	
		//		to_update_block.latest_included_mc_index = max_limci;
		//		updated_limci_blocks.push_back(to_update_block);
		//	
		//	for (auto updated_block : updated_limci_blocks)
		//		to_update_limci_blocks.remove(updated_block);

		//--update stable point
		//auto last_stable_block //get last stable block
		//auto witness_list //get witness list of last stable block
		//auto last_stable_block_children //get children of last stable block(children's best parent = last stable block)
		//auto mc_child //filter last_stable_block_children is_on_main_chain = 1
		//auto branch_children //filter last_stable_block_children is_on_main_chain = 0
		//auto free_main_chain_block	//get free and is_on_main_chain = true block
		//search up along best parent where level >= free_main_chain_block.witnessed_level
		//find min_wl = min(witnessed_leve) of all best parent whose account in witness_list
		//if branch_children.length == 0
		//	if(min_wl >= mc_child.level)
		//		advance_stable_mc_block(mc_child)
		//else 
		//	uint32_t branch_max_level;
		//	for (auto branch_root :branch_children)
		//		search down along best parent, find branch_child until free block
		//		if branch_child's witnessed_level > it's parent's witnessed_level
		//			branch_max_level = branch_child.level
		//  if min_wl > branch_max_level
		//		advance_stable_mc_block(mc_child)

	}

	void ledger_processor::advance_stable_mc_block(czr::block const & unstable_block)
	{
		//--update block stable
		//vector<block> stable_block_list;
		//set stable_block is_stable=true
		//stable_block_list.push_back(stable_block);
		//search along parents(except best parent) of unstable_block 
		//	if parent.main_chain_index == unstable_block.main_chain_index
		//		set parent is_stable=true
		//		stable_block_list.push_back(parent);

		//--resolve fork block
		//order stable_block_list by hash
		//for(auto stable_block:stable_block_list)
		//  if (statble_block.previous.is_zero() || statble_block.previous is_stable = true)
		//		if(!statble_block.previous.is_zero() && statble_block.previous is fork)
		//			statble_block.is_fork = true;	
		//		else
		//			if(statble_block.is_fork)
		//				auto successor(ledger.successor(transaction, stable_block.root()));
		//				assert(successor != nullptr && successor->hash() != block_hash);
		//				if successor is_stable != true
		//					statble_block.is_fork = false;
		//					successor.is_fork = true;
		//					change fork_block

		//					//rollbock account info
		//					ledger.rollback(transaction, successor->hash());

		//					//update account info
		//					czr::account_info info;
		//					ledger.store.account_get(transaction, block_a.hashables.account, info);
		//					ledger.change_latest(stable_block)

		//					//set predecessor
		//					set_predecessor predecessor (transaction_a, ledger.store, true);
		//					stable_block.visit(predecessor); 

		//					recursion change_latest by is_stable, main_chain_index asc, hash asc
		//				else
		//					statble_block.is_fork = true;	

		//--
		//	if(tatble_block.is_fork)
		//		handle fork block ?
		//	else
		//		if (*result.is_send)
		//		{
		//			czr::pending_key key(block_a.hashables.link, block_hash);
		//			czr::pending_info info(block_a.hashables.account, 0 - result.amount.number());
		//			ledger.store.pending_put(transaction, key, info);
		//		}
		//		else if (!block_a.hashables.link.is_zero())
		//		{
		//			ledger.store.pending_del(transaction, czr::pending_key(block_a.hashables.account, block_a.hashables.link));
		//		}
		//		
		//		check if need to receive block
		//		node.process_confirmed(block_a);

		//	vector<czr::skip_list_item> skip_list;
		//	if(is_on_main_chain == true)
		//		get and store skip_list_block_hash and skip_list_summary_hash
		//	caculate summary_hash by block_hash,all parent_summary_hash, all skip_list_summary_hash, is_fork
		//	store summary
		//	delete summary_hash from hash_tree_summary

		//update current stable main chain index
	}


	ledger_processor::ledger_processor(czr::ledger & ledger_a, MDB_txn * transaction_a) :
		ledger(ledger_a),
		transaction(transaction_a)
	{
	}
} // namespace

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

// Balance for account containing hash
czr::uint128_t czr::ledger::block_balance(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto block(store.block_get(transaction_a, hash_a));
	assert(block != nullptr);
	return block->hashables.balance.number();
}

// Return amount decrease or increase for block
czr::uint128_t czr::ledger::block_amount(MDB_txn * transaction_a, czr::block const & block_a)
{
	auto pre_balance(block_balance(transaction_a, block_a.hashables.previous));
	auto curr_balance(block_a.hashables.balance.number());
	return curr_balance < pre_balance ? pre_balance - curr_balance : curr_balance - pre_balance;
}

// Balance for an account by account number
czr::uint128_t czr::ledger::account_balance(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::uint128_t result(0);
	czr::account_info info;
	auto none(store.account_get(transaction_a, account_a, info));
	if (!none)
	{
		result = info.balance.number();
	}
	return result;
}

czr::uint128_t czr::ledger::account_pending(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::uint128_t result(0);
	czr::account end(account_a.number() + 1);
	for (auto i(store.pending_begin(transaction_a, czr::pending_key(account_a, 0))), n(store.pending_begin(transaction_a, czr::pending_key(end, 0))); i != n; ++i)
	{
		czr::pending_info info(i->second);
		result += info.amount.number();
	}
	return result;
}

czr::process_return czr::ledger::process(MDB_txn * transaction_a, czr::block const & block_a)
{
	ledger_processor processor(*this, transaction_a);
	block_a.visit(processor);
	return processor.result;
}

bool czr::ledger::block_exists(czr::block_hash const & hash_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	auto result(store.block_exists(transaction, hash_a));
	return result;
}

std::string czr::ledger::block_text(char const * hash_a)
{
	return block_text(czr::block_hash(hash_a));
}

std::string czr::ledger::block_text(czr::block_hash const & hash_a)
{
	std::string result;
	czr::transaction transaction(store.environment, nullptr, false);
	auto block(store.block_get(transaction, hash_a));
	if (block != nullptr)
	{
		block->serialize_json(result);
	}
	return result;
}

bool czr::ledger::is_send(MDB_txn * transaction_a, czr::block const & block_a)
{
	bool result(false);
	czr::block_hash previous(block_a.hashables.previous);
	if (!previous.is_zero())
	{
		if (block_a.hashables.balance < block_balance(transaction_a, previous))
		{
			result = true;
		}
	}
	return result;
}

czr::block_hash czr::ledger::block_destination(MDB_txn * transaction_a, czr::block const & block_a)
{
	czr::block_hash result(0);
	if (is_send(transaction_a, block_a))
	{
		result = block_a.hashables.link;
	}
	return result;
}

czr::block_hash czr::ledger::block_source(MDB_txn * transaction_a, czr::block const & block_a)
{
	czr::block_hash result;
	if (!is_send(transaction_a, block_a))
	{
		result = block_a.hashables.link;
	}
	return result;
}

// Rollback blocks until `block_a' doesn't exist
void czr::ledger::rollback(MDB_txn * transaction_a, czr::block_hash const & block_a)
{
	assert(store.block_exists(transaction_a, block_a));
	auto account_l(account(transaction_a, block_a));
	rollback_visitor rollback(transaction_a, *this);
	czr::account_info info;
	while (store.block_exists(transaction_a, block_a))
	{
		auto latest_error(store.account_get(transaction_a, account_l, info));
		assert(!latest_error);
		auto block(store.block_get(transaction_a, info.head));
		block->visit(rollback);
	}
}

// Return account containing hash
czr::account czr::ledger::account(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::account result;
	auto hash(hash_a);
	std::unique_ptr<czr::block> block(store.block_get(transaction_a, hash));
	result = block->hashables.account;
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

czr::checksum czr::ledger::checksum(MDB_txn * transaction_a, czr::account const & begin_a, czr::account const & end_a)
{
	czr::checksum result;
	auto error(store.checksum_get(transaction_a, 0, 0, result));
	assert(!error);
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

void czr::ledger::checksum_update(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::checksum value;
	auto error(store.checksum_get(transaction_a, 0, 0, value));
	assert(!error);
	value ^= hash_a;
	store.checksum_put(transaction_a, 0, 0, value);
}

void czr::ledger::change_latest(MDB_txn * transaction_a, czr::account const & account_a, czr::block_hash const & hash_a, czr::amount const & balance_a, uint64_t block_count_a)
{
	czr::account_info info;
	auto exists(!store.account_get(transaction_a, account_a, info));
	if (exists)
	{
		checksum_update(transaction_a, info.head);
	}
	else
	{
		assert(store.block_get(transaction_a, hash_a)->previous().is_zero());
		info.open_block = hash_a;
	}
	if (!hash_a.is_zero())
	{
		info.head = hash_a;
		info.balance = balance_a;
		info.modified = czr::seconds_since_epoch();
		info.block_count = block_count_a;
		store.account_put(transaction_a, account_a, info);

		checksum_update(transaction_a, hash_a);
	}
	else
	{
		store.account_del(transaction_a, account_a);
	}
}

std::unique_ptr<czr::block> czr::ledger::successor(MDB_txn * transaction_a, czr::block_hash const & block_a)
{
	assert(store.account_exists(transaction_a, block_a) || store.block_exists(transaction_a, block_a));
	assert(store.account_exists(transaction_a, block_a) || latest(transaction_a, account(transaction_a, block_a)) != block_a);
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
