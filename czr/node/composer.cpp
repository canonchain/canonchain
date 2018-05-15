#include <czr/node/composer.hpp>

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
	czr::raw_key const & prv_a , czr::public_key const & pub_a, uint64_t const & work_a)
{
	//my witness list
	czr::witness_list_info my_wl_info;
	bool exists(!ledger.store.my_witness_list_get(transaction_a, my_wl_info));
	if (!exists)
		return czr::compose_result(czr::compose_result_codes::witness_list_not_found, nullptr);

	//previous
	czr::account_info info;
	bool new_account(node.ledger.store.account_get(transaction_a, from_a, info));
	czr::block_hash previous = new_account ? 0 : info.head;

	//pick parents
	std::unique_ptr<std::list<czr::block_hash>> free_hashs(new std::list<czr::block_hash>);
	bool has_compatible(false);
	for (czr::store_iterator i(ledger.store.free_begin(transaction_a)), n(nullptr); i != n; ++i)
	{
		czr::free_key key(i->first);
		czr::block_hash free_hash(key.hash_asc);

		free_hashs->push_back(free_hash);

		if (!has_compatible)
		{
			//check compatible
			std::unique_ptr<czr::block> free_block(ledger.store.block_get(transaction_a, free_hash));
			czr::witness_list_info free_wl_info(ledger.block_witness_list(transaction_a, *free_block));
			if (my_wl_info.is_compatible(free_wl_info))
				has_compatible = true;
		}
	}

	std::vector<czr::account> parents;
	// we need at least one compatible parent, otherwise go deep
	if (!has_compatible)
	{
		//todo:pickDeepParentUnits
	}
	else
	{
		//todo:adjustParentsToNotRetreatWitnessedLevel
	}

	if (parents.size() == 0)
		return compose_result(czr::compose_result_codes::no_compatible_parent, nullptr);

	//last summary block
	uint64_t last_stable_mci(ledger.store.last_stable_mci_get(transaction_a));
	czr::block_hash last_summary_block;
	bool last_summary_block_error(ledger.store.main_chain_get(transaction_a, last_stable_mci, last_summary_block));
	assert(!last_summary_block_error);
	czr::summary_hash last_summary;
	bool last_summary_error(ledger.store.block_summary_get(transaction_a, last_summary_block, last_summary));
	assert(!last_summary_error);

	//todo:adjustLastStableMcBallAndParents

	//trim parents
	size_t max_parents_size(czr::max_parents_and_pervious_size);
	if (!previous.is_zero())
		max_parents_size -= 1;

	if (parents.size() > max_parents_size)
		parents.resize(max_parents_size);

	auto p(std::find(parents.begin(), parents.end(), previous));
	if (p != parents.end())
		parents.erase(p);

	//witness list block
	czr::witness_list_key search_wl_key(my_wl_info.hash(), 0);
	czr::store_iterator iter(ledger.store.witness_list_hash_block_begin(transaction_a, search_wl_key));

	czr::block_hash witness_list_block;
	if (iter != czr::store_iterator(nullptr))
	{
		czr::witness_list_key iter_wl_key(iter->first);
		if (iter_wl_key.hash == search_wl_key.hash && iter_wl_key.mci <= last_stable_mci)
		{
			witness_list_block = czr::mdb_val(iter->second).uint256();
		}
	}

	//witness list
	std::vector<czr::account> witness_list;
	if (witness_list_block.is_zero())
	{
		witness_list = my_wl_info.witness_list;
		std::sort(witness_list.begin(), witness_list.end());
	}

	//check witness list muatations along mc
	czr::block_hash best_parent_hash(ledger.determine_best_parent(transaction_a, parents, my_wl_info));
	ledger.check_witness_list_mutations_along_mc(transaction_a, best_parent_hash, my_wl_info, witness_list_block, last_summary_block);

	//check balance
	czr::amount balance(ledger.account_balance(transaction_a, from_a));
	czr::amount fee; //todo: calculate fee, !!parents count not relate to fee
	if (balance.number() < amount_a.number() + fee.number())
		return czr::compose_result(czr::compose_result_codes::insufficient_balance, nullptr);


	std::shared_ptr<czr::block> block(new czr::block(from_a, to_a, amount_a, previous, parents, 
		witness_list_block, witness_list, last_summary, last_summary_block, data_a, prv_a, pub_a, work_a));

	return czr::compose_result(czr::compose_result_codes::ok, block);
}