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

czr::keypair::keypair(czr::private_key const & prv_a)
{
	prv.data = prv_a;
	ed25519_publickey(prv_a.bytes.data(), pub.bytes.data());
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

czr::witness_list_info::witness_list_info(dev::RLP const & r)
{
	assert(r.isList());
	for (auto w : r)
	{
		witness_list.push_back((czr::account)w);
	}
	sort();
}

czr::witness_list_info::witness_list_info(std::vector<czr::account> const & list_a) :
	witness_list(list_a)
{
	sort();
}


void czr::witness_list_info::sort()
{
	std::sort(witness_list.begin(), witness_list.end());
}

void czr::witness_list_info::stream_RLP(dev::RLPStream & s) const
{
	s.appendList(witness_list.size());
	for (czr::account witness : witness_list)
		s << witness;
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
	uint8_t uncompatible_count(0);
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

czr::witness_list_key::witness_list_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::witness_list_key::operator==(czr::witness_list_key const & other) const
{
	return hash == other.hash && mci == other.mci;
}

czr::mdb_val czr::witness_list_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::witness_list_key *> (this));
}

czr::block_state::block_state() :
	is_fork(false),
	is_invalid(false),
	is_fail(false),
	is_free(false),
	is_stable(false),
	is_on_main_chain(false),
	main_chain_index(boost::none),
	latest_included_mc_index(boost::none),
	level(0),
	witnessed_level(0),
	best_parent(0),
	mc_timestamp(0),
	from_state(0),
	to_state(0)
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

void czr::block_state::serialize_json(boost::property_tree::ptree & tree)
{
	tree.put("is_free", is_free ? "1" : "0");
	tree.put("level", level);
	tree.put("witnessed_level", witnessed_level);
	tree.put("best_parent", best_parent.to_string());
	tree.put("is_stable", is_stable ? "1" : "0");
	tree.put("is_fork", is_fork ? "1" : "0");
	tree.put("is_invalid", is_invalid ? "1" : "0");
	tree.put("is_fail", is_fail ? "1" : "0");
	tree.put("is_on_mc", is_on_main_chain ? "1" : "0");
	tree.put("mci", main_chain_index ? std::to_string(*main_chain_index) : "null");
	tree.put("latest_included_mci", latest_included_mc_index ? std::to_string(*latest_included_mc_index) : "null");
	tree.put("mc_timestamp", mc_timestamp);
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

czr::skiplist_info::skiplist_info(dev::RLP const & r)
{
	assert(r.isList());
	for (auto sk : r)
		list.push_back((czr::block_hash) sk);
}

void czr::skiplist_info::stream_RLP(dev::RLPStream & s) const
{
	s.appendList(list.size());
	for (czr::block_hash sk : list)
		s << sk;
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

czr::joint_message::joint_message(std::shared_ptr<czr::block> block_a) :
	block(block_a)
{
}

czr::joint_message::joint_message(bool & error_a, dev::RLP const & r)
{
	if (error_a)
		return;

	error_a = r.itemCount() != 1 && r.itemCount() != 8;
	if (error_a)
		return;

	block = std::make_shared<czr::block>(error_a, r[0]);
	if (error_a)
		return;

	if (r.itemCount() > 1)
	{
		summary_hash = (czr::summary_hash)r[1];
		dev::RLP const & sk_list_rlp = r[2];
		block_skiplist.reserve(sk_list_rlp.itemCount());
		for (dev::RLP const & sk : sk_list_rlp)
			block_skiplist.push_back((czr::block_hash)sk);
		is_fork = (bool)r[3];
		is_invalid = (bool)r[4];
		is_fail = (bool)r[5];
		from_state = (czr::account_state_hash)r[6];
		to_state = (czr::account_state_hash)r[7];
	}
}

void czr::joint_message::stream_RLP(dev::RLPStream & s) const
{
	summary_hash.is_zero() ? s.appendList(1) : s.appendList(8);
	block->stream_RLP(s);
	if (!summary_hash.is_zero())
	{
		s << summary_hash;
		s.appendList(block_skiplist.size());
		for (czr::block_hash sk : block_skiplist)
			s << sk;
		s << is_fork << is_invalid << is_fail;
		s << from_state << to_state;
	}
}

//---
czr::unhandled_dependency_key::unhandled_dependency_key(czr::block_hash const & unhandled_a, czr::block_hash const & dependency_a):
	unhandled(unhandled_a),
	dependency(dependency_a)
{
}

czr::unhandled_dependency_key::unhandled_dependency_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::unhandled_dependency_key::operator==(czr::unhandled_dependency_key const & other_a) const
{
	return unhandled == other_a.unhandled && dependency == other_a.dependency;
}

czr::mdb_val czr::unhandled_dependency_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::unhandled_dependency_key *> (this));
}
//---
czr::dependency_unhandled_key::dependency_unhandled_key( czr::block_hash const & dependency_a,czr::block_hash const & unhandled_a) :
	dependency(dependency_a),
	unhandled(unhandled_a)
{
}

czr::dependency_unhandled_key::dependency_unhandled_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::dependency_unhandled_key::operator==(czr::dependency_unhandled_key const & other_a) const
{
	return  dependency == other_a.dependency&&unhandled == other_a.unhandled;
}

czr::mdb_val czr::dependency_unhandled_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::dependency_unhandled_key *> (this));
}

//---
czr::deadtime_unhandled_key::deadtime_unhandled_key(uint64_t const& deadtime_a, czr::block_hash const & unhandled_a):
	deadtime(deadtime_a), unhandled(unhandled_a)
{

}
czr::deadtime_unhandled_key::deadtime_unhandled_key(MDB_val const &val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

bool czr::deadtime_unhandled_key::operator== (czr::deadtime_unhandled_key const &other_a) const
{
	return  deadtime == other_a.deadtime&&unhandled == other_a.unhandled;
}

czr::mdb_val czr::deadtime_unhandled_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::deadtime_unhandled_key *> (this));
}

//---
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
