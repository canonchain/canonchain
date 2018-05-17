#include <czr/node/composer.hpp>

#include <unordered_set>

czr::compose_result::compose_result(czr::compose_result_codes const & code_a, std::shared_ptr<czr::block> block_a):
	code(code_a),
	block(block_a)
{
}

czr::composer::composer(czr::node & node_a):
	node(node_a),
	ledger(node_a.ledger)
{
}

czr::composer::~composer()
{
}

czr::compose_result czr::composer::compose(MDB_txn * transaction_a, czr::account const & from_a, czr::account const & to_a,
	czr::amount const & amount_a, std::vector<uint8_t> const & data_a,
	czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t const & work_a)
{
	if (data_a.size() > czr::max_data_size)
		return czr::compose_result(czr::compose_result_codes::data_size_too_large, nullptr);

	//my witness list
	czr::witness_list_info my_wl_info;
	bool exists(!ledger.store.my_witness_list_get(transaction_a, my_wl_info));
	if (!exists)
	{
		BOOST_LOG(node.log) << "compose error:my witness list not found";
		return czr::compose_result(czr::compose_result_codes::error, nullptr);
	}

	//previous
	czr::account_info info;
	bool new_account(node.ledger.store.account_get(transaction_a, from_a, info));
	czr::block_hash previous = new_account ? 0 : info.head;

	//pick parents and last summary
	std::vector<czr::block_hash> parents;
	czr::block_hash last_summary_block;
	czr::block_hash last_summary;
	uint64_t last_stable_mci;
	czr::block_hash witness_list_block;
	czr::error_message err_msg;
	pick_parents_and_last_summary_and_wl_block(err_msg, transaction_a, my_wl_info, last_summary_block, last_summary, last_stable_mci, witness_list_block);
	if (err_msg.error)
	{
		BOOST_LOG(node.log) << err_msg.message;
		return czr::compose_result(czr::compose_result_codes::error, nullptr);
	}

	//witness list
	std::vector<czr::account> witness_list;
	if (witness_list_block.is_zero())
	{
		witness_list = my_wl_info.witness_list;
		std::sort(witness_list.begin(), witness_list.end());
	}

	//exec timestamp
	uint64_t exec_timestamp(czr::seconds_since_epoch());
	for (czr::block_hash phash : parents)
	{
		std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction_a, phash));
		if (pblock->hashables.exec_timestamp > exec_timestamp)
		{
			BOOST_LOG(node.log) << "Parent's exec_timestamp later than yours";
			return czr::compose_result(czr::compose_result_codes::error, nullptr);
		}
	}

	//check balance
	czr::amount balance(ledger.account_balance(transaction_a, from_a));
	czr::amount fee; //todo: calculate fee, !!parents count not relate to fee
	if (balance.number() < amount_a.number() + fee.number())
		return czr::compose_result(czr::compose_result_codes::insufficient_balance, nullptr);

	std::shared_ptr<czr::block> block(new czr::block(from_a, to_a, amount_a, previous, parents, 
		witness_list_block, witness_list, last_summary, last_summary_block, data_a, exec_timestamp, prv_a, pub_a, work_a));

	return czr::compose_result(czr::compose_result_codes::ok, block);
}

void czr::composer::pick_parents_and_last_summary_and_wl_block(czr::error_message & err_msg, MDB_txn * transaction_a, czr::witness_list_info const & my_wl_info, 
	czr::block_hash & last_summary_block, czr::summary_hash & last_summary, uint64_t & last_stable_mci, czr::block_hash & witness_list_block)
{
	//pick free parents
	std::vector<czr::account> parents;
	bool has_compatible(false);
	for (czr::store_iterator i(ledger.store.free_begin(transaction_a)), n(nullptr); i != n; ++i)
	{
		czr::free_key key(i->first);
		czr::block_hash free_hash(key.hash_asc);

		parents.push_back(free_hash);

		if (!has_compatible)
		{
			//check compatible
			std::unique_ptr<czr::block> free_block(ledger.store.block_get(transaction_a, free_hash));
			czr::witness_list_info free_wl_info(ledger.block_witness_list(transaction_a, *free_block));
			if (my_wl_info.is_compatible(free_wl_info))
				has_compatible = true;
		}
	}

	// we need at least one compatible parent, otherwise go deep
	if (!has_compatible)
	{
		czr::error_message err_msg;
		parents = pick_deep_parents(err_msg, transaction_a, my_wl_info, boost::none);
		if (err_msg.error)
			return;
	}
	else
	{
		adjust_parents_to_not_retreat_witnessed_level(transaction_a, my_wl_info, parents);
		std::sort(parents.begin(), parents.end());
	}

	if (parents.size() == 0)
	{
		err_msg.error = true;
		err_msg.message = boost::str(boost::format("compose error:no compatible parent, my witness list: %1%") % my_wl_info.to_string());
		return;
	}

	//first trim parents
	if (parents.size() > czr::max_parents_size)
	{
		parents.resize(czr::max_parents_size);
	}

	//last mc summary block
	uint64_t last_stable_mc_mci(ledger.store.last_stable_mci_get(transaction_a));
	bool last_summary_block_error(ledger.store.main_chain_get(transaction_a, last_stable_mc_mci, last_summary_block));
	assert(!last_summary_block_error);

	//last_summary_block and parents may be adjusted
	adjust_last_summary_and_parents(err_msg, transaction_a, my_wl_info, last_summary_block, parents);
	if (err_msg.error)
		return;

	//get last_stable_mci and last_summary after adjustment
	czr::block_state last_summary_state;
	bool last_summary_state_error(ledger.store.block_state_get(transaction_a, last_summary_block, last_summary_state));
	assert(!last_summary_state_error);
	last_stable_mci = *last_summary_state.main_chain_index;

	bool last_summary_error(ledger.store.block_summary_get(transaction_a, last_summary_block, last_summary));
	assert(!last_summary_error);

	//second trim parents
	if (parents.size() > czr::max_parents_size)
	{
		std::random_shuffle(parents.begin(), parents.end());

		std::vector<czr::block_hash> witness_parents;
		std::vector<czr::block_hash> non_witness_parents;
		for (czr::block_hash phash : parents)
		{
			std::unique_ptr<czr::block> pblock(ledger.store.block_get(transaction_a, phash));
			assert(pblock != nullptr);

			czr::witness_list_info p_wl_info(ledger.block_witness_list(transaction_a, *pblock));
			for (czr::account my_witness : my_wl_info.witness_list)
			{
				if (p_wl_info.contains(my_witness))
				{
					witness_parents.push_back(phash);
					continue;
				}
			}

			non_witness_parents.push_back(phash);
		}

		//witness parent first
		parents = witness_parents;
		if (parents.size() >= max_parents_size)
		{
			parents.resize(max_parents_size);
		}
		else
		{
			int push_count = max_parents_size - parents.size();
			for (int i = 0; i < push_count; i++)
			{
				parents.push_back(non_witness_parents[i]);
			}
		}
	}

	//check witness list muatations along mc
	czr::block_hash best_parent_hash(ledger.determine_best_parent(transaction_a, parents, my_wl_info));
	if (best_parent_hash.is_zero())
	{
		std::stringstream p_ss;
		size_t size(parents.size());
		for (int i = 0; i < parents.size(); i++)
		{
			p_ss << parents[i].to_string();
			if (i < size - 1)
				p_ss << ",";
		}
		err_msg.error = true;
		err_msg.message = boost::str(boost::format("compose error:no compatible best parent, parents: %1%, my witness list: %2%")
			% p_ss.str() % my_wl_info.to_string());
		return;
	}

	//witness list block
	witness_list_block = ledger.find_witness_list_block(transaction_a, my_wl_info, last_stable_mci);

	bool is_mutations_ok(ledger.check_witness_list_mutations_along_mc(transaction_a, best_parent_hash, my_wl_info, witness_list_block, last_summary_block));
	if (!is_mutations_ok)
	{
		err_msg.error = true;
		err_msg.message = boost::str(boost::format("compose error:mutations fail, best parent: %1%, my witness list: %2%, witness list block: %3%, last summary block: %4%")
			% best_parent_hash.to_string() % my_wl_info.to_string() % witness_list_block.to_string() % last_summary_block.to_string());
		return;
	}
}

std::vector<czr::block_hash> czr::composer::pick_deep_parents(czr::error_message & err_msg, MDB_txn * transaction_a, 
	czr::witness_list_info const & my_wl_info, boost::optional<uint64_t> const & max_wl)
{
	std::vector<czr::block_hash> parents;

	if (!max_wl)
	{
		//search all block order by mci desc
		for(czr::store_iterator i(ledger.store.mci_block_rbeign(transaction_a)), n(nullptr); i != n; ++i )
		{
			czr::mci_block_key key(i->first);
			czr::block_hash b_hash(key.hash);
			std::unique_ptr<czr::block> block(ledger.store.block_get(transaction_a, b_hash));
			czr::witness_list_info wl_info(ledger.block_witness_list(transaction_a, *block));
			if (my_wl_info.is_compatible(wl_info))
			{
				parents.push_back(b_hash);
				break;
			}
		}
	}
	else
	{
		//search main chain block
		for (czr::store_iterator i(ledger.store.main_chain_rbegin(transaction_a)), n(nullptr); i != n; ++i)
		{
			czr::block_hash b_hash(i->second.uint256());
			czr::block_state b_state;
			bool b_state_error(ledger.store.block_state_get(transaction_a, b_hash, b_state));
			assert(!b_state_error);
			if (b_state.witnessed_level < *max_wl)
			{
				std::unique_ptr<czr::block> block(ledger.store.block_get(transaction_a, b_hash));
				czr::witness_list_info wl_info(ledger.block_witness_list(transaction_a, *block));
				if (my_wl_info.is_compatible(wl_info))
				{
					parents.push_back(b_hash);
					break;
				}
			}
		}
	}

	if (parents.size() == 0)
	{
		err_msg.error = true;
		err_msg.message = boost::str(boost::format("compose error:no deep parents, my witness list: %1%") % my_wl_info.to_string());
		return parents;
	}

	return check_witnessed_level_not_retreating_and_look_lower(err_msg, transaction_a, my_wl_info, parents);
}

std::vector<czr::block_hash> czr::composer::check_witnessed_level_not_retreating_and_look_lower(czr::error_message & err_msg, MDB_txn * transaction_a,
	czr::witness_list_info const & my_wl_info, std::vector<czr::block_hash> const & parents)
{
	czr::block_hash best_parent_hash(ledger.determine_best_parent(transaction_a, parents, my_wl_info));
	assert(!best_parent_hash.is_zero());
	czr::block_state best_parent_state;
	bool best_parent_state_error(ledger.store.block_state_get(transaction_a, best_parent_hash, best_parent_state));
	assert(!best_parent_state_error);

	uint64_t best_parent_wl(best_parent_state.witnessed_level);
	uint64_t child_wl(ledger.determine_witness_level(transaction_a, best_parent_hash, my_wl_info));

	if (child_wl >= best_parent_wl)
		return parents;
	else
		return pick_deep_parents(err_msg, transaction_a, my_wl_info, best_parent_wl);
}

void czr::composer::adjust_parents_to_not_retreat_witnessed_level(MDB_txn * transaction_a,
	czr::witness_list_info const & my_wl_info, std::vector<czr::block_hash> & parents)
{

	std::shared_ptr<std::unordered_set<block_hash>> all_excluded_hashs(new std::unordered_set<block_hash>);
	while (true)
	{
		czr::block_hash best_parent_hash(ledger.determine_best_parent(transaction_a, parents, my_wl_info));
		assert(!best_parent_hash.is_zero());
		czr::block_state best_parent_state;
		bool best_parent_state_error(ledger.store.block_state_get(transaction_a, best_parent_hash, best_parent_state));
		assert(!best_parent_state_error);

		uint64_t best_parent_wl(best_parent_state.witnessed_level);
		uint64_t child_wl(ledger.determine_witness_level(transaction_a, best_parent_hash, my_wl_info));

		if (child_wl >= best_parent_wl)
			return;
		else
			replace_excluded_parent(transaction_a, best_parent_hash, parents, all_excluded_hashs);
	}
}

void czr::composer::replace_excluded_parent(MDB_txn * transaction_a, 
	czr::block_hash const & excluded_hash, std::vector<czr::block_hash> & parents, std::shared_ptr<std::unordered_set<block_hash>> all_excluded_hashs)
{
	all_excluded_hashs->insert(excluded_hash);
	auto p(std::find(parents.begin(), parents.end(), excluded_hash));
	if (p != parents.end())
		parents.erase(p);

	std::unique_ptr<czr::block> excluded_block(ledger.store.block_get(transaction_a, excluded_hash));
	assert(excluded_block != nullptr);

	for (czr::block_hash pb_hash : excluded_block->parents())
	{
		bool has_other_children(false);
		czr::store_iterator iter(ledger.store.block_child_begin(transaction_a, czr::block_child_key(pb_hash, 0)));
		czr::store_iterator iter_end(nullptr);
		while(iter != iter_end)
		{
			czr::block_child_key key(iter->first);
			if (key.hash != pb_hash)
				break;

			if (all_excluded_hashs->find(key.child_hash) == all_excluded_hashs->end())
			{
				has_other_children = true;
				break;
			}
		}

		if (!has_other_children)
		{
			parents.push_back(pb_hash);
		}
	}
}

void czr::composer::adjust_last_summary_and_parents(czr::error_message & err_msg, MDB_txn * transaction_a, czr::witness_list_info const & my_wl_info, czr::block_hash & last_summary_block_hash, std::vector<czr::block_hash> & parents)
{
	bool is_stable(ledger.check_stable_from_later_blocks(transaction_a, last_summary_block_hash, parents));
	if (is_stable)
		return;

	if (parents.size() > 1)
	{
		parents = pick_deep_parents(err_msg, transaction_a, my_wl_info, boost::none);
		if (err_msg.error)
			return;
	}
	else
	{
		czr::block_state last_summary_state;
		bool last_summary_state_error(ledger.store.block_state_get(transaction_a, last_summary_block_hash, last_summary_state));
		assert(!last_summary_state_error);

		last_summary_block_hash = last_summary_state.best_parent;
	}
	adjust_last_summary_and_parents(err_msg, transaction_a, my_wl_info, last_summary_block_hash, parents);
}