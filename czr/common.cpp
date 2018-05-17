#include <czr/common.hpp>
#include <czr/blockstore.hpp>
#include <czr/node/common.hpp>
#include <queue>
#include <ed25519-donna/ed25519.h>

// Create a new random keypair
czr::keypair::keypair()
{
	random_pool.GenerateBlock(prv.data.bytes.data(), prv.data.bytes.size());
	ed25519_publickey(prv.data.bytes.data(), pub.bytes.data());
}

// Create a keypair given a hex string of the private key
czr::keypair::keypair(std::string const & prv_a)
{
	auto error(prv.data.decode_hex(prv_a));
	assert(!error);
	ed25519_publickey(prv.data.bytes.data(), pub.bytes.data());
}

czr::account_info::account_info() :
	head(0),
	open_block(0),
	modified(0),
	block_count(0)
{
}

czr::account_info::account_info(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	static_assert (sizeof(head) + sizeof(open_block) + sizeof(modified) + sizeof(block_count) + sizeof(first_good_stable_mci) == sizeof(*this), "Class not packed");
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::account_info::account_info(czr::block_hash const & head_a, czr::block_hash const & open_block_a, uint64_t modified_a, uint64_t block_count_a) :
	head(head_a),
	open_block(open_block_a),
	modified(modified_a),
	block_count(block_count_a)
{
}

void czr::account_info::serialize(czr::stream & stream_a) const
{
	write(stream_a, head.bytes);
	write(stream_a, open_block.bytes);
	write(stream_a, modified);
	write(stream_a, block_count);
}

bool czr::account_info::deserialize(czr::stream & stream_a)
{
	auto error(read(stream_a, head.bytes));
	if (!error)
	{
		error = read(stream_a, open_block.bytes);
		if (!error)
		{
			error = read(stream_a, modified);
			if (!error)
			{
				error = read(stream_a, block_count);
			}
		}
	}
	return error;
}

bool czr::account_info::operator== (czr::account_info const & other_a) const
{
	return head == other_a.head && open_block == other_a.open_block && modified == other_a.modified && block_count == other_a.block_count;
}

bool czr::account_info::operator!= (czr::account_info const & other_a) const
{
	return !(*this == other_a);
}

czr::mdb_val czr::account_info::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::account_info *> (this));
}

czr::witness_list_info::witness_list_info()
{
}

czr::witness_list_info::witness_list_info(MDB_val const & val_a)
{
	assert(false);
	//todo:serialize///////////////
	//std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + val_a.mv_size, reinterpret_cast<uint8_t *> (this));
}

czr::witness_list_info::witness_list_info(std::vector<czr::account> const & list_a) :
	witness_list(list_a)
{
}

czr::mdb_val czr::witness_list_info::val() const
{
	assert(false);
	//todo:serialize///////////////
	return czr::mdb_val(sizeof(*this), const_cast<czr::witness_list_info *> (this));
}

czr::witness_list_hash czr::witness_list_info::hash() const
{
	czr::uint256_union result;
	blake2b_state hash_l;
	auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
	assert(status == 0);

	for (czr::uint256_union item : witness_list)
		blake2b_update(&hash_l, item.bytes.data(), sizeof(item.bytes));

	status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
	assert(status == 0);
	return result;
}

bool czr::witness_list_info::is_compatible(witness_list_info const & other_a) const
{
	uint8_t uncompatible_count;
	for (auto w : witness_list)
	{
		auto iter(std::find(other_a.witness_list.begin(), other_a.witness_list.end(), w));
		if (iter == other_a.witness_list.end())
		{
			uncompatible_count++;
			if (uncompatible_count > czr::max_witness_list_mutations)
				return false;
		}
	}
	return true;
}

bool czr::witness_list_info::contains(czr::account const & account_a) const
{
	auto iter = std::find(witness_list.begin(), witness_list.end(), account_a);
	return iter != witness_list.end();
}

std::string czr::witness_list_info::to_string() const
{
	std::stringstream ss;
	size_t size(witness_list.size());
	for (int i = 0; i < size; i++)
	{
		czr::account witness(witness_list[i]);
		ss << witness.to_account();
		if (i < size - 1)
			ss << ",";
	}
	return ss.str();
}

czr::witness_list_key::witness_list_key(czr::witness_list_hash const & hash_a, uint64_t const & mci_a) :
	hash(hash_a),
	mci(mci_a)
{
}

czr::witness_list_key::witness_list_key(MDB_val const &)
{
}

bool czr::witness_list_key::operator==(czr::witness_list_key const &) const
{
	return false;
}

czr::mdb_val czr::witness_list_key::val() const
{
	return czr::mdb_val();
}

czr::block_state::block_state()
{
}

czr::block_state::block_state(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::mdb_val czr::block_state::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::block_state *> (this));
}

czr::free_key::free_key(uint64_t const & witnessed_level_a, uint64_t const & level_a, czr::block_hash const & hash_a) :
	witnessed_level_desc(std::numeric_limits<uint64_t>::max() - witnessed_level_a),
	level_asc(level_a),
	hash_asc(hash_a)
{
}

czr::free_key::free_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::free_key::operator==(czr::free_key const & other) const
{
	return witnessed_level_desc == other.witnessed_level_desc
		&& level_asc == other.level_asc
		&& hash_asc == other.hash_asc;
}

czr::mdb_val czr::free_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::free_key *> (this));
}

czr::block_child_key::block_child_key(czr::block_hash const & hash_a, czr::block_hash const & child_hash_a) :
	hash(hash_a),
	child_hash(child_hash_a)
{
}

czr::block_child_key::block_child_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::block_child_key::operator==(czr::block_child_key const & other) const
{
	return hash == other.hash && child_hash == other.child_hash;
}

czr::mdb_val czr::block_child_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::block_child_key *> (this));
}

czr::account_state::account_state() :
	account(0),
	block_hash(0),
	pervious(0),
	balance(0)
{
}

czr::account_state::account_state(czr::account const & account_a, czr::block_hash const & block_hash_a, czr::account_state_hash const & pervious_a, czr::amount const & balance_a):
	account(account_a),
	block_hash(block_hash_a),
	pervious(pervious_a),
	balance(balance_a)
{
}

czr::account_state::account_state(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::mdb_val czr::account_state::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::account_state *> (this));
}

czr::account_state_hash czr::account_state::hash()
{
	czr::account_state_hash result;
	blake2b_state hash_l;
	auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
	assert(status == 0);

	blake2b_update(&hash_l, account.bytes.data(), sizeof(account.bytes));
	blake2b_update(&hash_l, block_hash.bytes.data(), sizeof(block_hash.bytes));
	blake2b_update(&hash_l, pervious.bytes.data(), sizeof(pervious.bytes));
	blake2b_update(&hash_l, balance.bytes.data(), sizeof(balance.bytes));

	status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
	assert(status == 0);

	return result;
}

czr::skiplist_info::skiplist_info(std::vector<czr::block_hash> const & list_a) :
	list(list_a)
{
}

czr::skiplist_info::skiplist_info(MDB_val const &)
{
	assert(false);
	//todo:serialize///////////////
}

czr::mdb_val czr::skiplist_info::val() const
{
	assert(false);
	//todo:serialize///////////////
	return czr::mdb_val(sizeof(*this), const_cast<czr::skiplist_info *> (this));
}

czr::mci_block_key::mci_block_key(uint64_t const & mci_a, czr::block_hash const & hash_a):
	mci(mci_a),
	hash(hash_a)
{
}

czr::mci_block_key::mci_block_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::mci_block_key::operator==(czr::mci_block_key const & other_a) const
{
	return mci == other_a.mci && hash == other_a.hash;
}

czr::mdb_val czr::mci_block_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::mci_block_key *> (this));
}

czr::summary_hash czr::summary::gen_summary_hash(czr::block_hash const & block_hash, std::vector<czr::summary_hash> const & parent_hashs,
	std::set<czr::summary_hash> const & skiplist, bool const & is_fork, bool const & is_invalid, bool const & is_fail,
	czr::account_state_hash const & from_state_hash, czr::account_state_hash const & to_state_hash)
{
	czr::summary_hash result;
	blake2b_state hash_l;
	auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
	assert(status == 0);

	blake2b_update(&hash_l, block_hash.bytes.data(), sizeof(block_hash.bytes));
	for (auto & parent : parent_hashs)
		blake2b_update(&hash_l, parent.bytes.data(), sizeof(parent.bytes));
	for (auto & s : skiplist)
		blake2b_update(&hash_l, s.bytes.data(), sizeof(s.bytes));
	blake2b_update(&hash_l, &is_fork, sizeof(is_fork));
	blake2b_update(&hash_l, &is_invalid, sizeof(is_invalid));
	blake2b_update(&hash_l, &is_fail, sizeof(is_fail));
	blake2b_update(&hash_l, from_state_hash.bytes.data(), sizeof(from_state_hash));
	blake2b_update(&hash_l, to_state_hash.bytes.data(), sizeof(to_state_hash));

	status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
	assert(status == 0);

	return result;
}

std::unique_ptr<czr::block> czr::deserialize_block(MDB_val const & val_a)
{
	czr::bufferstream stream(reinterpret_cast<uint8_t const *> (val_a.mv_data), val_a.mv_size);
	return deserialize_block(stream);
}
