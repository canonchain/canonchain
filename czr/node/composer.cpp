#include <czr/node/composer.hpp>

czr::compose_result::compose_result(czr::compose_result_codes const & code_a, std::shared_ptr<czr::block> block_a):
	code(code_a),
	block(block_a)
{
}

czr::compose_parents_result::compose_parents_result(czr::compose_result_codes const & code_a, std::vector<czr::account> const & parents_a):
	code(code_a),
	parents(parents_a)
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
	//get previous
	czr::account_info info;
	bool new_account(node.ledger.store.account_get(transaction_a, from_a, info));
	czr::block_hash previous = new_account ? 0 : info.head;

	//last summary block
	uint64_t last_stable_mci(ledger.store.last_stable_mci_get(transaction_a));
	czr::block_hash last_summary_block;
	bool last_summary_block_error(ledger.store.main_chain_get(transaction_a, last_stable_mci, last_summary_block));
	assert(!last_summary_block_error);
	czr::summary_hash last_summary;
	bool last_summary_error(ledger.store.block_summary_get(transaction_a, last_summary_block, last_summary));
	assert(!last_summary_error);

	//my witness list
	czr::witness_list_info my_wl_info;
	bool exists(!ledger.store.my_witness_list_get(transaction_a, my_wl_info));
	if (!exists)
		return czr::compose_result(czr::compose_result_codes::witness_list_not_found, nullptr);

	czr::uint256_union my_wl_hash(my_wl_info.hash());
	czr::block_hash witness_list_block;
	bool wl_block_exists(!ledger.store.witness_list_hash_block_get(transaction_a, my_wl_hash, witness_list_block));
	std::vector<czr::account> witness_list;
	if (!wl_block_exists)
	{
		witness_list = my_wl_info.witness_list;
		std::sort(witness_list.begin(), witness_list.end());
	}

	czr::amount balance(ledger.account_balance(transaction_a, from_a));
	czr::amount fee; //todo: calculate fee, !!parents count not relate to fee
	if (balance.number() < amount_a.number() + fee.number())
		return czr::compose_result(czr::compose_result_codes::insufficient_balance, nullptr);

	//todo:select parents
	std::vector<czr::block_hash> parents;

	std::shared_ptr<czr::block> block(new czr::block(from_a, to_a, amount_a, previous, parents, 
		witness_list_block, witness_list, last_summary, last_summary_block, data_a, prv_a, pub_a, work_a));

	return czr::compose_result(czr::compose_result_codes::ok, block);
}

czr::compose_parents_result czr::composer::compose_parents(MDB_txn * transaction_a, czr::witness_list_info my_wl_info)
{
	std::vector<czr::account> parents;

	return compose_parents_result(czr::compose_result_codes::ok, parents);
}

