#include <czr/blockstore.hpp>
#include <czr/ledger.hpp>
#include <czr/node/common.hpp>

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

void czr::ledger::change_account_latest(MDB_txn * transaction_a, czr::account const & account_a, czr::block_hash const & hash_a, uint64_t const & block_count_a)
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
		auto wl_not_found(store.block_witnesslist_get(transaction_a, block_a.hashables.witness_list_block, wl_info));
		assert(!wl_not_found);
	}
	else
	{
		wl_info = czr::witness_list_info(block_a.hashables.witness_list);
	}
	return wl_info;
}

