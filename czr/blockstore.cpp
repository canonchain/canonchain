#include <queue>
#include <czr/blockstore.hpp>

namespace
{
	/**
	* Fill in our predecessors
	*/
	class set_predecessor : public czr::block_visitor
	{
	public:
		set_predecessor(MDB_txn * transaction_a, czr::block_store & store_a, bool is_force_a) :
			transaction(transaction_a),
			store(store_a),
			is_force(is_force_a)
		{
		}
		virtual ~set_predecessor() = default;
		void fill_value(czr::block const & block_a)
		{
			auto value(store.block_get_raw(transaction, block_a.previous()));
			assert(value.mv_size != 0);

			bool is_change = is_force;
			if (!is_force)
			{
				czr::block_hash successor_hash;
				czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.mv_data) + value.mv_size - successor_hash.bytes.size(), successor_hash.bytes.size());
				auto error(czr::read(stream, successor_hash.bytes));
				is_change = successor_hash.is_zero();
			}

			if (is_change)
			{
				auto hash(block_a.hash());
				std::vector<uint8_t> data(static_cast<uint8_t *> (value.mv_data), static_cast<uint8_t *> (value.mv_data) + value.mv_size);
				std::copy(hash.bytes.begin(), hash.bytes.end(), data.end() - hash.bytes.size());
				store.block_put_raw(transaction, store.blocks, block_a.previous(), czr::mdb_val(data.size(), data.data()));
			}
		}
		void block(czr::block const & block_a) override
		{
			if (!block_a.previous().is_zero())
			{
				fill_value(block_a);
			}
		}
		MDB_txn * transaction;
		czr::block_store & store;
		bool is_force;
	};
}

czr::store_entry::store_entry() :
	first(0, nullptr),
	second(0, nullptr)
{
}

void czr::store_entry::clear()
{
	first = { 0, nullptr };
	second = { 0, nullptr };
}

czr::store_entry * czr::store_entry::operator-> ()
{
	return this;
}

czr::store_entry & czr::store_iterator::operator-> ()
{
	return current;
}

czr::store_iterator::store_iterator(MDB_txn * transaction_a, MDB_dbi db_a) :
	cursor(nullptr)
{
	auto status(mdb_cursor_open(transaction_a, db_a, &cursor));
	assert(status == 0);
	auto status2(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_FIRST));
	assert(status2 == 0 || status2 == MDB_NOTFOUND);
	if (status2 != MDB_NOTFOUND)
	{
		auto status3(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_GET_CURRENT));
		assert(status3 == 0 || status3 == MDB_NOTFOUND);
	}
	else
	{
		current.clear();
	}
}

czr::store_iterator::store_iterator(std::nullptr_t) :
	cursor(nullptr)
{
}

czr::store_iterator::store_iterator(MDB_txn * transaction_a, MDB_dbi db_a, MDB_val const & val_a) :
	cursor(nullptr)
{
	auto status(mdb_cursor_open(transaction_a, db_a, &cursor));
	assert(status == 0);
	current.first.value = val_a;
	auto status2(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_SET_RANGE));
	assert(status2 == 0 || status2 == MDB_NOTFOUND);
	if (status2 != MDB_NOTFOUND)
	{
		auto status3(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_GET_CURRENT));
		assert(status3 == 0 || status3 == MDB_NOTFOUND);
	}
	else
	{
		current.clear();
	}
}

czr::store_iterator::store_iterator(czr::store_iterator && other_a)
{
	cursor = other_a.cursor;
	other_a.cursor = nullptr;
	current = other_a.current;
}

czr::store_iterator::~store_iterator()
{
	if (cursor != nullptr)
	{
		mdb_cursor_close(cursor);
	}
}

czr::store_iterator & czr::store_iterator::operator++ ()
{
	assert(cursor != nullptr);
	auto status(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_NEXT));
	if (status == MDB_NOTFOUND)
	{
		current.clear();
	}
	return *this;
}

void czr::store_iterator::next_dup()
{
	assert(cursor != nullptr);
	auto status(mdb_cursor_get(cursor, &current.first.value, &current.second.value, MDB_NEXT_DUP));
	if (status == MDB_NOTFOUND)
	{
		current.clear();
	}
}

czr::store_iterator & czr::store_iterator::operator= (czr::store_iterator && other_a)
{
	if (cursor != nullptr)
	{
		mdb_cursor_close(cursor);
	}
	cursor = other_a.cursor;
	other_a.cursor = nullptr;
	current = other_a.current;
	other_a.current.clear();
	return *this;
}

bool czr::store_iterator::operator== (czr::store_iterator const & other_a) const
{
	auto result(current.first.data() == other_a.current.first.data());
	assert(!result || (current.first.size() == other_a.current.first.size()));
	assert(!result || (current.second.data() == other_a.current.second.data()));
	assert(!result || (current.second.size() == other_a.current.second.size()));
	return result;
}

bool czr::store_iterator::operator!= (czr::store_iterator const & other_a) const
{
	return !(*this == other_a);
}

czr::store_iterator czr::block_store::unchecked_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, unchecked);
	return result;
}

czr::store_iterator czr::block_store::unchecked_begin(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::store_iterator result(transaction_a, unchecked, czr::mdb_val(hash_a));
	return result;
}

czr::store_iterator czr::block_store::unchecked_end()
{
	czr::store_iterator result(nullptr);
	return result;
}

czr::block_store::block_store(bool & error_a, boost::filesystem::path const & path_a, int lmdb_max_dbs) :
	environment(error_a, path_a, lmdb_max_dbs),
	accounts(0),
	pending(0),
	unchecked(0),
	unsynced(0),
	checksum(0),
	block_witnesslist(0),
	witnesslisthash_block(0),
	free(0),
	block_state(0),
	summary(0),
	skiplist(0)
{
	if (!error_a)
	{
		czr::transaction transaction(environment, nullptr, true);
		error_a |= mdb_dbi_open(transaction, "accounts", MDB_CREATE, &accounts) != 0;
		error_a |= mdb_dbi_open(transaction, "blocks", MDB_CREATE, &blocks) != 0;
		error_a |= mdb_dbi_open(transaction, "pending", MDB_CREATE, &pending) != 0;
		error_a |= mdb_dbi_open(transaction, "unchecked", MDB_CREATE | MDB_DUPSORT, &unchecked) != 0;
		error_a |= mdb_dbi_open(transaction, "unsynced", MDB_CREATE, &unsynced) != 0;
		error_a |= mdb_dbi_open(transaction, "checksum", MDB_CREATE, &checksum) != 0;
		error_a |= mdb_dbi_open(transaction, "meta", MDB_CREATE, &meta) != 0;
		error_a |= mdb_dbi_open(transaction, "block_witnesslist", MDB_CREATE, &block_witnesslist) != 0;
		error_a |= mdb_dbi_open(transaction, "witnesslisthash_block", MDB_CREATE, &witnesslisthash_block) != 0;
		error_a |= mdb_dbi_open(transaction, "free", MDB_CREATE, &free) != 0;
		error_a |= mdb_dbi_open(transaction, "block_state", MDB_CREATE, &block_state) != 0;
		error_a |= mdb_dbi_open(transaction, "summary", MDB_CREATE, &summary) != 0;
		error_a |= mdb_dbi_open(transaction, "skiplist", MDB_CREATE, &skiplist) != 0;
		if (!error_a)
		{
			checksum_put(transaction, 0, 0, 0);
		}
	}
}

void czr::block_store::version_put(MDB_txn * transaction_a, int version_a)
{
	czr::uint256_union version_key(1);
	czr::uint256_union version_value(version_a);
	auto status(mdb_put(transaction_a, meta, czr::mdb_val(version_key), czr::mdb_val(version_value), 0));
	assert(status == 0);
}

int czr::block_store::version_get(MDB_txn * transaction_a)
{
	czr::uint256_union version_key(1);
	czr::mdb_val data;
	auto error(mdb_get(transaction_a, meta, czr::mdb_val(version_key), data));
	int result;
	if (error == MDB_NOTFOUND)
	{
		result = 1;
	}
	else
	{
		czr::uint256_union version_value(data.uint256());
		assert(version_value.qwords[2] == 0 && version_value.qwords[1] == 0 && version_value.qwords[0] == 0);
		result = version_value.number().convert_to<int>();
	}
	return result;
}

void czr::block_store::clear(MDB_dbi db_a)
{
	czr::transaction transaction(environment, nullptr, true);
	auto status(mdb_drop(transaction, db_a, 0));
	assert(status == 0);
}

void czr::block_store::block_put_raw(MDB_txn * transaction_a, MDB_dbi database_a, czr::block_hash const & hash_a, MDB_val value_a)
{
	auto status2(mdb_put(transaction_a, database_a, czr::mdb_val(hash_a), &value_a, 0));
	assert(status2 == 0);
}

void czr::block_store::block_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block const & block_a, czr::block_hash const & successor_a)
{
	assert(successor_a.is_zero() || block_exists(transaction_a, successor_a));
	std::vector<uint8_t> vector;
	{
		czr::vectorstream stream(vector);
		block_a.serialize(stream);
		czr::write(stream, successor_a.bytes);
	}
	block_put_raw(transaction_a, blocks, hash_a, { vector.size(), vector.data() });
	set_predecessor predecessor(transaction_a, *this, false);
	block_a.visit(predecessor);
	assert(block_a.previous().is_zero() || block_successor(transaction_a, block_a.previous()) == hash_a);
}

MDB_val czr::block_store::block_get_raw(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::mdb_val result;
	auto status(mdb_get(transaction_a, blocks, czr::mdb_val(hash_a), result));
	assert(status == 0 || status == MDB_NOTFOUND);
	return result;
}

std::unique_ptr<czr::block> czr::block_store::block_get(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto value(block_get_raw(transaction_a, hash_a));
	std::unique_ptr<czr::block> result;
	if (value.mv_size != 0)
	{
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.mv_data), value.mv_size);
		result = czr::deserialize_block(stream);
		assert(result != nullptr);
	}
	return result;
}

void czr::block_store::block_del(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_del(transaction_a, blocks, czr::mdb_val(hash_a), nullptr));
	assert(status == 0);
}

bool czr::block_store::block_exists(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto exists(true);
	czr::mdb_val junk;
	auto status(mdb_get(transaction_a, blocks, czr::mdb_val(hash_a), junk));
	assert(status == 0 || status == MDB_NOTFOUND);
	exists = status == 0;
	return exists;
}

czr::store_iterator czr::block_store::block_begin(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	czr::store_iterator result(transaction_a, blocks, czr::mdb_val(hash_a));
	return result;
}

std::unique_ptr<czr::block> czr::block_store::block_random(MDB_txn * transaction_a)
{
	czr::block_hash hash;
	czr::random_pool.GenerateBlock(hash.bytes.data(), hash.bytes.size());
	czr::store_iterator existing(transaction_a, blocks, czr::mdb_val(hash));
	if (existing == czr::store_iterator(nullptr))
	{
		existing = czr::store_iterator(transaction_a, blocks);
	}
	assert(existing != czr::store_iterator(nullptr));
	return block_get(transaction_a, czr::block_hash(existing->first.uint256()));
}

czr::block_hash czr::block_store::block_successor(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto value(block_get_raw(transaction_a, hash_a));
	czr::block_hash result;
	if (value.mv_size != 0)
	{
		assert(value.mv_size >= result.bytes.size());
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.mv_data) + value.mv_size - result.bytes.size(), result.bytes.size());
		auto error(czr::read(stream, result.bytes));
		assert(!error);
	}
	else
	{
		result.clear();
	}
	return result;
}

void czr::block_store::block_successor_clear(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto block(block_get(transaction_a, hash_a));
	block_put(transaction_a, hash_a, *block);
}

size_t czr::block_store::block_count(MDB_txn * transaction_a)
{
	MDB_stat stats;
	auto status(mdb_stat(transaction_a, blocks, &stats));
	assert(status == 0);
	return stats.ms_entries;
}

void czr::block_store::account_del(MDB_txn * transaction_a, czr::account const & account_a)
{
	auto status(mdb_del(transaction_a, accounts, czr::mdb_val(account_a), nullptr));
	assert(status == 0);
}

bool czr::block_store::account_exists(MDB_txn * transaction_a, czr::account const & account_a)
{
	auto iterator(latest_begin(transaction_a, account_a));
	return iterator != czr::store_iterator(nullptr) && czr::account(iterator->first.uint256()) == account_a;
}

bool czr::block_store::account_get(MDB_txn * transaction_a, czr::account const & account_a, czr::account_info & info_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, accounts, czr::mdb_val(account_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.data()), value.size());
		result = info_a.deserialize(stream);
		assert(!result);
	}
	return result;
}

void czr::block_store::account_put(MDB_txn * transaction_a, czr::account const & account_a, czr::account_info const & info_a)
{
	auto status(mdb_put(transaction_a, accounts, czr::mdb_val(account_a), info_a.val(), 0));
	assert(status == 0);
}

void czr::block_store::pending_put(MDB_txn * transaction_a, czr::pending_key const & key_a, czr::pending_info const & pending_a)
{
	auto status(mdb_put(transaction_a, pending, key_a.val(), pending_a.val(), 0));
	assert(status == 0);
}

void czr::block_store::pending_del(MDB_txn * transaction_a, czr::pending_key const & key_a)
{
	auto status(mdb_del(transaction_a, pending, key_a.val(), nullptr));
	assert(status == 0);
}

bool czr::block_store::pending_exists(MDB_txn * transaction_a, czr::pending_key const & key_a)
{
	auto iterator(pending_begin(transaction_a, key_a));
	return iterator != czr::store_iterator(nullptr) && czr::pending_key(iterator->first) == key_a;
}

bool czr::block_store::pending_get(MDB_txn * transaction_a, czr::pending_key const & key_a, czr::pending_info & pending_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, pending, key_a.val(), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		result = false;
		assert(value.size() == sizeof(pending_a.source.bytes) + sizeof(pending_a.amount.bytes));
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.data()), value.size());
		auto error1(czr::read(stream, pending_a.source));
		assert(!error1);
		auto error2(czr::read(stream, pending_a.amount));
		assert(!error2);
	}
	return result;
}

czr::store_iterator czr::block_store::pending_begin(MDB_txn * transaction_a, czr::pending_key const & key_a)
{
	czr::store_iterator result(transaction_a, pending, key_a.val());
	return result;
}

czr::store_iterator czr::block_store::pending_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, pending);
	return result;
}

czr::store_iterator czr::block_store::pending_end()
{
	czr::store_iterator result(nullptr);
	return result;
}

void czr::block_store::unchecked_clear(MDB_txn * transaction_a)
{
	auto status(mdb_drop(transaction_a, unchecked, 0));
	assert(status == 0);
}

void czr::block_store::unchecked_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, std::shared_ptr<czr::block> const & block_a)
{
	// Checking if same unchecked block is already in database
	bool exists(false);
	auto block_hash(block_a->hash());
	auto cached(unchecked_get(transaction_a, hash_a));
	for (auto i(cached.begin()), n(cached.end()); i != n && !exists; ++i)
	{
		if ((*i)->hash() == block_hash)
		{
			exists = true;
		}
	}
	// Inserting block if it wasn't found in database
	if (!exists)
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		unchecked_cache.insert(std::make_pair(hash_a, block_a));
	}
}

std::vector<std::shared_ptr<czr::block>> czr::block_store::unchecked_get(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	std::vector<std::shared_ptr<czr::block>> result;
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		for (auto i(unchecked_cache.find(hash_a)), n(unchecked_cache.end()); i != n && i->first == hash_a; ++i)
		{
			result.push_back(i->second);
		}
	}
	for (auto i(unchecked_begin(transaction_a, hash_a)), n(unchecked_end()); i != n && czr::block_hash(i->first.uint256()) == hash_a; i.next_dup())
	{
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (i->second.data()), i->second.size());
		result.push_back(czr::deserialize_block(stream));
	}
	return result;
}

void czr::block_store::unchecked_del(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block const & block_a)
{
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		for (auto i(unchecked_cache.find(hash_a)), n(unchecked_cache.end()); i != n && i->first == hash_a;)
		{
			if (*i->second == block_a)
			{
				i = unchecked_cache.erase(i);
			}
			else
			{
				++i;
			}
		}
	}
	std::vector<uint8_t> vector;
	{
		czr::vectorstream stream(vector);
		block_a.serialize(stream);
	}
	auto status(mdb_del(transaction_a, unchecked, czr::mdb_val(hash_a), czr::mdb_val(vector.size(), vector.data())));
	assert(status == 0 || status == MDB_NOTFOUND);
}

size_t czr::block_store::unchecked_count(MDB_txn * transaction_a)
{
	MDB_stat unchecked_stats;
	auto status(mdb_stat(transaction_a, unchecked, &unchecked_stats));
	assert(status == 0);
	auto result(unchecked_stats.ms_entries);
	return result;
}

void czr::block_store::unsynced_put(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_put(transaction_a, unsynced, czr::mdb_val(hash_a), czr::mdb_val(0, nullptr), 0));
	assert(status == 0);
}

void czr::block_store::unsynced_del(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_del(transaction_a, unsynced, czr::mdb_val(hash_a), nullptr));
	assert(status == 0);
}

bool czr::block_store::unsynced_exists(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto iterator(unsynced_begin(transaction_a, hash_a));
	return iterator != czr::store_iterator(nullptr) && czr::block_hash(iterator->first.uint256()) == hash_a;
}

czr::store_iterator czr::block_store::unsynced_begin(MDB_txn * transaction_a)
{
	return czr::store_iterator(transaction_a, unsynced);
}

czr::store_iterator czr::block_store::unsynced_begin(MDB_txn * transaction_a, czr::uint256_union const & val_a)
{
	return czr::store_iterator(transaction_a, unsynced, czr::mdb_val(val_a));
}

czr::store_iterator czr::block_store::unsynced_end()
{
	return czr::store_iterator(nullptr);
}

void czr::block_store::checksum_put(MDB_txn * transaction_a, uint64_t prefix, uint8_t mask, czr::uint256_union const & hash_a)
{
	assert((prefix & 0xff) == 0);
	uint64_t key(prefix | mask);
	auto status(mdb_put(transaction_a, checksum, czr::mdb_val(sizeof(key), &key), czr::mdb_val(hash_a), 0));
	assert(status == 0);
}

bool czr::block_store::checksum_get(MDB_txn * transaction_a, uint64_t prefix, uint8_t mask, czr::uint256_union & hash_a)
{
	assert((prefix & 0xff) == 0);
	uint64_t key(prefix | mask);
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, checksum, czr::mdb_val(sizeof(key), &key), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == 0)
	{
		result = false;
		czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.data()), value.size());
		auto error(czr::read(stream, hash_a));
		assert(!error);
	}
	else
	{
		result = true;
	}
	return result;
}

void czr::block_store::checksum_del(MDB_txn * transaction_a, uint64_t prefix, uint8_t mask)
{
	assert((prefix & 0xff) == 0);
	uint64_t key(prefix | mask);
	auto status(mdb_del(transaction_a, checksum, czr::mdb_val(sizeof(key), &key), nullptr));
	assert(status == 0);
}

void czr::block_store::flush(MDB_txn * transaction_a)
{
	std::unordered_multimap<czr::block_hash, std::shared_ptr<czr::block>> unchecked_cache_l;
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		unchecked_cache_l.swap(unchecked_cache);
	}
	for (auto & i : unchecked_cache_l)
	{
		std::vector<uint8_t> vector;
		{
			czr::vectorstream stream(vector);
			i.second->serialize(stream);
		}
		auto status(mdb_put(transaction_a, unchecked, czr::mdb_val(i.first), czr::mdb_val(vector.size(), vector.data()), 0));
		assert(status == 0);
	}
}

czr::store_iterator czr::block_store::latest_begin(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::store_iterator result(transaction_a, accounts, czr::mdb_val(account_a));
	return result;
}

czr::store_iterator czr::block_store::latest_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, accounts);
	return result;
}

czr::store_iterator czr::block_store::latest_end()
{
	czr::store_iterator result(nullptr);
	return result;
}

bool czr::block_store::summary_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::uint256_union & summary_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, summary, czr::mdb_val(hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		summary_a = value.uint256();
		assert(!result);
	}
	return result;
}

void czr::block_store::summary_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::uint256_union const & summary_a)
{
	auto status(mdb_put(transaction_a, summary, czr::mdb_val(hash_a), czr::mdb_val(summary_a), 0));
	assert(status == 0);
}

bool czr::block_store::witnesslisthash_block_get(MDB_txn * transaction_a, czr::witness_list_hash const & hash_a, czr::block_hash & block_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, witnesslisthash_block, czr::mdb_val(hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		block_a = value.uint256();
		assert(!result);
	}
	return result;
}

bool czr::block_store::witnesslisthash_block_exists(MDB_txn * transaction_a, czr::witness_list_hash const & hash_a)
{
	czr::store_iterator iterator(transaction_a, witnesslisthash_block, czr::mdb_val(hash_a));
	return iterator != czr::store_iterator(nullptr) && iterator->first.uint256() == hash_a;
}

void czr::block_store::witnesslisthash_block_put(MDB_txn * transaction_a, czr::witness_list_hash const & hash_a, czr::block_hash const & block_a)
{
	auto status(mdb_put(transaction_a, witnesslisthash_block, czr::mdb_val(hash_a), czr::mdb_val(block_a), 0));
	assert(status == 0);
}

bool czr::block_store::block_witnesslist_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::witness_list_info & info_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, block_witnesslist, czr::mdb_val(hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		info_a = czr::witness_list_info(value);
		assert(!result);
	}
	return result;
}

void czr::block_store::block_witnesslist_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::witness_list_info const & info_a)
{
	auto status(mdb_put(transaction_a, block_witnesslist, czr::mdb_val(hash_a), info_a.val(), 0));
	assert(status == 0);
}

void czr::block_store::free_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::free_block const & free_block_a)
{
	auto status(mdb_put(transaction_a, free, czr::mdb_val(hash_a), free_block_a.val(), 0));
	assert(status == 0);
}

void czr::block_store::free_del(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_del(transaction_a, free, czr::mdb_val(hash_a), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}

bool czr::block_store::block_state_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block_state & state_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, block_state, czr::mdb_val(hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		state_a = czr::block_state(value);
		assert(!result);
	}
	return result;
}

void czr::block_store::block_state_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block_state const & free_block_a)
{
	auto status(mdb_put(transaction_a, block_state, czr::mdb_val(hash_a), free_block_a.val(), 0));
	assert(status == 0);
}
