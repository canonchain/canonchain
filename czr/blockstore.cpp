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
		set_predecessor(MDB_txn * transaction_a, czr::block_store & store_a, bool force_set_a) :
			transaction(transaction_a),
			store(store_a),
			force_set(force_set_a)
		{
		}
		virtual ~set_predecessor() = default;
		void fill_value(czr::block const & block_a)
		{
			auto value(store.block_get_raw(transaction, block_a.previous()));
			assert(value.mv_size != 0);

			bool is_set = force_set;
			if (!force_set)
			{
				czr::block_hash successor_hash;
				czr::bufferstream stream(reinterpret_cast<uint8_t const *> (value.mv_data) + value.mv_size - successor_hash.bytes.size(), successor_hash.bytes.size());
				auto error(czr::read(stream, successor_hash.bytes));
				is_set = successor_hash.is_zero();
			}

			if (is_set)
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
		bool force_set;
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

czr::store_iterator::store_iterator(MDB_txn *, MDB_dbi):
	cursor(nullptr)
{
}

czr::store_iterator::store_iterator(MDB_txn * transaction_a, MDB_dbi db_a, czr::store_iterator_direction direction_a) :
	cursor(nullptr),
	direction(direction_a)
{
	auto status(mdb_cursor_open(transaction_a, db_a, &cursor));
	assert(status == 0);
	auto status2(mdb_cursor_get(cursor, &current.first.value, &current.second.value, direction == czr::store_iterator_direction::forward ? MDB_FIRST : MDB_LAST));
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
	direction = other_a.direction;
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
	auto status(mdb_cursor_get(cursor, &current.first.value, &current.second.value, direction == czr::store_iterator_direction::forward ? MDB_NEXT : MDB_PREV));
	if (status == MDB_NOTFOUND)
	{
		current.clear();
	}
	return *this;
}

void czr::store_iterator::next_dup()
{
	assert(cursor != nullptr);
	auto status(mdb_cursor_get(cursor, &current.first.value, &current.second.value, direction == czr::store_iterator_direction::forward ? MDB_NEXT_DUP : MDB_PREV_DUP));
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


czr::block_store::block_store(bool & error_a, boost::filesystem::path const & path_a, int lmdb_max_dbs) :
	environment(error_a, path_a, lmdb_max_dbs),
	accounts(0),
	account_state(0),
	latest_account_state(0),
	blocks(0),
	unchecked(0),
	meta(0),
	block_witness_list(0),
	witness_list_hash_block(0),
	block_state(0),
	block_child(0),
	free(0),
	unstable(0),
	main_chain(0),
	mci_block(0),
	block_summary(0),
	summary_block(0),
	skiplist(0),
	fork_successor(0),
	prop(0)
{
	if (!error_a)
	{
		czr::transaction transaction(environment, nullptr, true);
		error_a |= mdb_dbi_open(transaction, "accounts", MDB_CREATE, &accounts) != 0;
		error_a |= mdb_dbi_open(transaction, "account_state", MDB_CREATE, &account_state) != 0;
		error_a |= mdb_dbi_open(transaction, "latest_account_state", MDB_CREATE, &latest_account_state) != 0;
		error_a |= mdb_dbi_open(transaction, "blocks", MDB_CREATE, &blocks) != 0;
		error_a |= mdb_dbi_open(transaction, "unchecked", MDB_CREATE | MDB_DUPSORT, &unchecked) != 0;
		error_a |= mdb_dbi_open(transaction, "meta", MDB_CREATE, &meta) != 0;
		error_a |= mdb_dbi_open(transaction, "block_witness_list", MDB_CREATE, &block_witness_list) != 0;
		error_a |= mdb_dbi_open(transaction, "witness_list_hash_block", MDB_CREATE, &witness_list_hash_block) != 0;
		error_a |= mdb_dbi_open(transaction, "block_state", MDB_CREATE, &block_state) != 0;
		error_a |= mdb_dbi_open(transaction, "block_child", MDB_CREATE, &block_child) != 0;
		error_a |= mdb_dbi_open(transaction, "free", MDB_CREATE, &free) != 0;
		error_a |= mdb_dbi_open(transaction, "unstable", MDB_CREATE, &unstable) != 0;
		error_a |= mdb_dbi_open(transaction, "main_chain", MDB_CREATE, &main_chain) != 0;
		error_a |= mdb_dbi_open(transaction, "mci_block", MDB_CREATE, &mci_block) != 0;
		error_a |= mdb_dbi_open(transaction, "block_summary", MDB_CREATE, &block_summary) != 0;
		error_a |= mdb_dbi_open(transaction, "summary_block", MDB_CREATE, &summary_block) != 0;
		error_a |= mdb_dbi_open(transaction, "skiplist", MDB_CREATE, &skiplist) != 0;
		error_a |= mdb_dbi_open(transaction, "fork_successor", MDB_CREATE, &fork_successor) != 0;
		error_a |= mdb_dbi_open(transaction, "prop", MDB_CREATE, &prop) != 0;
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
		dev::bytesConstRef data_cref(reinterpret_cast<uint8_t const *> (value.mv_data), value.mv_size - sizeof(czr::block_hash));
		dev::RLP r(data_cref);
		result = czr::interpret_block_RLP(r);
		assert(result != nullptr);
	}
	return result;
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

size_t czr::block_store::block_count(MDB_txn * transaction_a)
{
	MDB_stat stats;
	auto status(mdb_stat(transaction_a, blocks, &stats));
	assert(status == 0);
	return stats.ms_entries;
}

void czr::block_store::block_put_raw(MDB_txn * transaction_a, MDB_dbi database_a, czr::block_hash const & hash_a, MDB_val value_a)
{
	auto status2(mdb_put(transaction_a, database_a, czr::mdb_val(hash_a), &value_a, 0));
	assert(status2 == 0);
}

void czr::block_store::block_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block const & block_a, czr::block_hash const & successor_a)
{
	assert(successor_a.is_zero() || block_exists(transaction_a, successor_a));

	dev::bytes b;
	{
		dev::RLPStream s;
		block_a.stream_RLP(s);
		s.swapOut(b);
	}
	b.insert(b.end(), successor_a.bytes.begin(), successor_a.bytes.end());

	block_put_raw(transaction_a, blocks, hash_a, { b.size(), b.data() });
	block_predecessor_set(transaction_a, block_a, false);
	assert(block_a.previous().is_zero() || block_successor(transaction_a, block_a.previous()) == hash_a);
}


void czr::block_store::block_predecessor_set(MDB_txn * transaction_a, czr::block const & block_a, bool const & force_set)
{
	set_predecessor predecessor(transaction_a, *this, force_set);
	block_a.visit(predecessor);
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



void czr::block_store::account_del(MDB_txn * transaction_a, czr::account const & account_a)
{
	auto status(mdb_del(transaction_a, accounts, czr::mdb_val(account_a), nullptr));
	assert(status == 0);
}

bool czr::block_store::account_exists(MDB_txn * transaction_a, czr::account const & account_a)
{
	auto iterator(account_begin(transaction_a, account_a));
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

czr::store_iterator czr::block_store::account_begin(MDB_txn * transaction_a, czr::account const & account_a)
{
	czr::store_iterator result(transaction_a, accounts, czr::mdb_val(account_a));
	return result;
}

czr::store_iterator czr::block_store::account_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, accounts);
	return result;
}

czr::store_iterator czr::block_store::account_end()
{
	czr::store_iterator result(nullptr);
	return result;
}


bool czr::block_store::account_state_get(MDB_txn * transaction_a, czr::account_state_hash const & hash_a, czr::account_state value_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, account_state, czr::mdb_val(hash_a), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		value_a = czr::account_state(value);
		assert(!result);
	}
	return result;
}

void czr::block_store::account_state_put(MDB_txn * transaction_a, czr::account_state_hash const & hash_a, czr::account_state const & value_a)
{
	auto status(mdb_put(transaction_a, account_state, czr::mdb_val(hash_a), value_a.val(), 0));
	assert(status == 0);
}


bool czr::block_store::latest_account_state_get(MDB_txn * transaction_a, czr::account const & account_a, czr::account_state value_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, latest_account_state, czr::mdb_val(account_a), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		value_a = czr::account_state(value);
		assert(!result);
	}
	return result;
}

void czr::block_store::latest_account_state_put(MDB_txn * transaction_a, czr::account const & account_a, czr::account_state const & value_a)
{
	auto status(mdb_put(transaction_a, latest_account_state, czr::mdb_val(account_a), value_a.val(), 0));
	assert(status == 0);
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
		dev::bytesConstRef data_cref(reinterpret_cast<byte const *> (i->second.data()), i->second.size());
		dev::RLP r(data_cref);
		result.push_back(czr::interpret_block_RLP(r));
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
	dev::bytes data;
	{
		dev::RLPStream s;
		block_a.stream_RLP(s);
		s.swapOut(data);
	}
	auto status(mdb_del(transaction_a, unchecked, czr::mdb_val(hash_a), czr::mdb_val(data.size(), data.data())));
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

void czr::block_store::flush(MDB_txn * transaction_a)
{
	std::unordered_multimap<czr::block_hash, std::shared_ptr<czr::block>> unchecked_cache_l;
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		unchecked_cache_l.swap(unchecked_cache);
	}
	for (auto & i : unchecked_cache_l)
	{
		std::vector<uint8_t> data;
		{
			dev::RLPStream s;
			i.second->stream_RLP(s);
			s.swapOut(data);
		}
		auto status(mdb_put(transaction_a, unchecked, czr::mdb_val(i.first), czr::mdb_val(data.size(), data.data()), 0));
		assert(status == 0);
	}
}


bool czr::block_store::block_summary_get(MDB_txn * transaction_a, czr::block_hash const & block_hash_a, czr::summary_hash & summary_hash_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, block_summary, czr::mdb_val(block_hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		summary_hash_a = value.uint256();
		assert(!result);
	}
	return result;
}

void czr::block_store::block_summary_put(MDB_txn * transaction_a, czr::block_hash const & block_hash_a, czr::summary_hash const & summary_hash_a)
{
	auto status(mdb_put(transaction_a, block_summary, czr::mdb_val(block_hash_a), czr::mdb_val(summary_hash_a), 0));
	assert(status == 0);
}


bool czr::block_store::summary_block_get(MDB_txn * transaction_a, czr::summary_hash const &  summary_hash_a, czr::block_hash & block_hash_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, summary_block, czr::mdb_val(summary_hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		block_hash_a = value.uint256();
		assert(!result);
	}
	return result;
}

void czr::block_store::summary_block_put(MDB_txn * transaction_a, czr::summary_hash const & summary_hash_a, czr::block_hash const & block_hash_a)
{
	auto status(mdb_put(transaction_a, summary_block, czr::mdb_val(summary_hash_a), czr::mdb_val(block_hash_a), 0));
	assert(status == 0);
}


bool czr::block_store::witness_list_hash_block_get(MDB_txn * transaction_a, czr::witness_list_key const & key_a, czr::block_hash & block_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, witness_list_hash_block, key_a.val(), value));
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

czr::store_iterator czr::block_store::witness_list_hash_block_begin(MDB_txn * transaction_a, czr::witness_list_key const & key_a)
{
	czr::store_iterator iterator(transaction_a, witness_list_hash_block, key_a.val());
	return iterator;
}

bool czr::block_store::witness_list_hash_block_exists(MDB_txn * transaction_a, czr::witness_list_key const & key_a)
{
	czr::store_iterator iterator(transaction_a, witness_list_hash_block, key_a.val());
	return iterator != czr::store_iterator(nullptr) && czr::witness_list_key(iterator->first) == key_a;
}

void czr::block_store::witness_list_hash_block_put(MDB_txn * transaction_a, czr::witness_list_key const & key_a, czr::block_hash const & block_a)
{
	auto status(mdb_put(transaction_a, witness_list_hash_block, key_a.val(), czr::mdb_val(block_a), 0));
	assert(status == 0);
}


bool czr::block_store::block_witness_list_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::witness_list_info & info_a)
{
	czr:mdb_val value;
	auto status(mdb_get(transaction_a, block_witness_list, czr::mdb_val(hash_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		dev::RLP r(reinterpret_cast<byte *>(value.data()), value.size());
		info_a = czr::witness_list_info(r);
		assert(!result);
	}
	return result;
}

void czr::block_store::block_witness_list_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::witness_list_info const & info_a)
{
	dev::bytes b;
	{
		dev::RLPStream s;
		info_a.stream_RLP(s);
		s.swapOut(b);
	}
	auto status(mdb_put(transaction_a, block_witness_list, czr::mdb_val(hash_a), czr::mdb_val(b.size(), b.data()), 0));
	assert(status == 0);
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

void czr::block_store::block_state_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::block_state const & state_a)
{
	auto status(mdb_put(transaction_a, block_state, czr::mdb_val(hash_a), state_a.val(), 0));
	assert(status == 0);
}


czr::store_iterator czr::block_store::free_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, free);
	return result;
}

void czr::block_store::free_put(MDB_txn * transaction_a, czr::free_key const & key_a)
{
	auto status(mdb_put(transaction_a, free, key_a.val(), czr::mdb_val(), 0));
	assert(status == 0);
}

void czr::block_store::free_del(MDB_txn * transaction_a, czr::free_key const & key_a)
{
	auto status(mdb_del(transaction_a, free, key_a.val(), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}


czr::store_iterator czr::block_store::unstable_begin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, unstable);
	return result;
}

void czr::block_store::unstable_put(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_put(transaction_a, unstable, czr::mdb_val(hash_a), czr::mdb_val(), 0));
	assert(status == 0);
}

void czr::block_store::unstable_del(MDB_txn * transaction_a, czr::block_hash const & hash_a)
{
	auto status(mdb_del(transaction_a, unstable, czr::mdb_val(hash_a), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}


bool czr::block_store::main_chain_get(MDB_txn * transaction_a, uint64_t const & mci, czr::block_hash & hash_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, main_chain, czr::mdb_val(mci), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		hash_a = value.uint256();
		assert(!result);
	}
	return result;
}

czr::store_iterator czr::block_store::main_chain_begin(MDB_txn * transaction_a, uint64_t const & mci)
{
	czr::store_iterator result(transaction_a, main_chain, czr::mdb_val(mci));
	return result;
}

czr::store_iterator czr::block_store::main_chain_rbegin(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, main_chain, czr::store_iterator_direction::reverse);
	return result;
}

void czr::block_store::main_chain_put(MDB_txn * transaction_a, uint64_t const & mci, czr::block_hash const & hash_a)
{
	auto status(mdb_put(transaction_a, main_chain, czr::mdb_val(mci), czr::mdb_val(hash_a), 0));
	assert(status == 0);
}

void czr::block_store::main_chain_del(MDB_txn * transaction_a, uint64_t const & mci)
{
	auto status(mdb_del(transaction_a, main_chain, czr::mdb_val(mci), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}

czr::store_iterator czr::block_store::mci_block_beign(MDB_txn * transaction_a, czr::mci_block_key const & key)
{
	czr::store_iterator result(transaction_a, mci_block, key.val());
	return result;
}

czr::store_iterator czr::block_store::mci_block_rbeign(MDB_txn * transaction_a)
{
	czr::store_iterator result(transaction_a, mci_block, czr::store_iterator_direction::reverse);
	return result;
}

void czr::block_store::mci_block_put(MDB_txn * transaction_a, czr::mci_block_key const & key)
{
	auto status(mdb_put(transaction_a, mci_block, key.val(), czr::mdb_val(), 0));
	assert(status == 0);
}

void czr::block_store::mci_block_del(MDB_txn * transaction_a, czr::mci_block_key const & key)
{
	auto status(mdb_del(transaction_a, mci_block, key.val(), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}


void czr::block_store::last_stable_mci_put(MDB_txn * transaction_a, uint64_t const & last_stable_mci_value)
{
	auto status(mdb_put(transaction_a, prop, czr::mdb_val(last_stable_mci_key), czr::mdb_val(last_stable_mci_value), 0));
	assert(status == 0);
}

uint64_t czr::block_store::last_stable_mci_get(MDB_txn * transaction_a)
{
	czr::mdb_val value;
	auto error(mdb_get(transaction_a, prop, czr::mdb_val(last_stable_mci_key), value));
	int result;
	if (error != MDB_NOTFOUND)
		result = value.uint64();
	return result;
}


czr::store_iterator czr::block_store::block_child_begin(MDB_txn * transaction_a, czr::block_child_key const & key_a)
{
	czr::store_iterator result(transaction_a, block_child, key_a.val());
	return result;
}

void czr::block_store::block_child_put(MDB_txn * transaction_a, czr::block_child_key const & key_a)
{
	auto status(mdb_put(transaction_a, block_child, key_a.val(), czr::mdb_val(), 0));
	assert(status == 0);
}


bool czr::block_store::skiplist_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::skiplist_info skiplist_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, skiplist, czr::mdb_val(hash_a), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		dev::RLP r(reinterpret_cast<byte *>(value.data()), value.size());
		skiplist_a = czr::skiplist_info(r);
		assert(!result);
	}
	return result;
}

void czr::block_store::skiplist_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::skiplist_info const & skiplist_a)
{
	dev::bytes b;
	{
		dev::RLPStream s;
		skiplist_a.stream_RLP(s);
		s.swapOut(b);
	}
	auto status(mdb_put(transaction_a, skiplist, czr::mdb_val(hash_a), czr::mdb_val(b.size(), b.data()), 0));
	assert(status == 0);
}


bool czr::block_store::fork_successor_get(MDB_txn * transaction_a, czr::block_hash const & pervious_hash_a, czr::block_hash hash_a)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, fork_successor, czr::mdb_val(pervious_hash_a), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		hash_a = value.uint256();
		assert(!result);
	}
	return result;
}

void czr::block_store::fork_successor_put(MDB_txn * transaction_a, czr::block_hash const & pervious_hash_a, czr::block_hash const & hash_a)
{
	auto status(mdb_put(transaction_a, fork_successor, czr::mdb_val(pervious_hash_a), czr::mdb_val(hash_a), 0));
	assert(status == 0);
}

void czr::block_store::fork_successor_del(MDB_txn * transaction_a, czr::block_hash const & pervious_hash_a)
{
	auto status(mdb_del(transaction_a, fork_successor, czr::mdb_val(pervious_hash_a), nullptr));
	assert(status == 0);
}


bool czr::block_store::genesis_hash_get(MDB_txn * transaction_a, czr::block_hash & genesis_hash)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, prop, czr::mdb_val(genesis_hash_key), value));
	bool error(false);
	if (status == MDB_NOTFOUND)
	{
		error = true;
	}
	else
	{
		genesis_hash = value.uint256();
		assert(!error);
	}
	return error;
}

void czr::block_store::genesis_hash_put(MDB_txn * transaction_a, czr::block_hash const & genesis_hash)
{
	auto status(mdb_put(transaction_a, prop, czr::mdb_val(genesis_hash_key), czr::mdb_val(genesis_hash), 0));
	assert(status == 0);
}


bool czr::block_store::my_witness_list_get(MDB_txn * transaction_a, czr::witness_list_info my_wl_info)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, prop, czr::mdb_val(my_witness_list_key), value));
	bool result;
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		dev::RLP r(reinterpret_cast<byte *>(value.data()), value.size());
		my_wl_info = czr::witness_list_info(r);
		assert(!result);
	}
	return result;
}

void czr::block_store::my_witness_list_put(MDB_txn * transaction_a, czr::witness_list_info my_wl_info)
{
	dev::bytes b;
	{
		dev::RLPStream s;
		my_wl_info.stream_RLP(s);
		s.swapOut(b);
	}
	auto status(mdb_put(transaction_a, prop, czr::mdb_val(my_witness_list_key), czr::mdb_val(b.size(), b.data()), 0));
	assert(status == 0);
}

czr::uint256_union const czr::block_store::genesis_hash_key(0); 
czr::uint256_union const czr::block_store::last_stable_mci_key(1);
czr::uint256_union const czr::block_store::my_witness_list_key(2);
