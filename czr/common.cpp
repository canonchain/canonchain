#include <czr/common.hpp>

#include <czr/blockstore.hpp>
#include <czr/node/common.hpp>

#include <boost/property_tree/json_parser.hpp>

#include <queue>

#include <ed25519-donna/ed25519.h>

// Genesis keys for network variants
namespace
{
	char const * test_private_key_data = "34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4";
	char const * test_public_key_data = "B0311EA55708D6A53C75CDBF88300259C6D018522FE3D4D0A242E431F9E8B6D0"; // czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo
	char const * beta_public_key_data = "0311B25E0D1E1D7724BBA5BD523954F1DBCFC01CB8671D55ED2D32C7549FB252"; // czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1
	char const * live_public_key_data = "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA"; // czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3

																											//todo:modify genesis_data///////////////////////
	char const * test_genesis_data = R"%%%({
	"source": "B0311EA55708D6A53C75CDBF88300259C6D018522FE3D4D0A242E431F9E8B6D0",
	"account": "czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
	"work": "9680625b39d3363d",
	"signature": "ECDA914373A2F0CA1296475BAEE40500A7F0A7AD72A5A80C81D7FAB7F6C802B2CC7DB50F5DD0FB25B2EF11761FA7344A158DD5A700B21BD47DE5BD0F63153A02"
})%%%";

	char const * beta_genesis_data = R"%%%({
	"source": "0311B25E0D1E1D7724BBA5BD523954F1DBCFC01CB8671D55ED2D32C7549FB252",
	"account": "czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
	"work": "869e17b2bfa36639",
	"signature": "34DF447C7F185673128C3516A657DFEC7906F16C68FB5A8879432E2E4FB908C8ED0DD24BBECFAB3C7852898231544A421DC8CB636EF66C82E1245083EB08EA0F"
})%%%";

	char const * live_genesis_data = R"%%%({
	"source": "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA",
	"account": "czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

	class ledger_constants
	{
	public:
		ledger_constants() :
			zero_key("0"),
			test_genesis_key(test_private_key_data),
			czr_test_account(test_public_key_data),
			czr_beta_account(beta_public_key_data),
			czr_live_account(live_public_key_data),
			czr_test_genesis(test_genesis_data),
			czr_beta_genesis(beta_genesis_data),
			czr_live_genesis(live_genesis_data),
			genesis_account(czr::czr_network == czr::czr_networks::czr_test_network ? czr_test_account : czr::czr_network == czr::czr_networks::czr_beta_network ? czr_beta_account : czr_live_account),
			genesis_block(czr::czr_network == czr::czr_networks::czr_test_network ? czr_test_genesis : czr::czr_network == czr::czr_networks::czr_beta_network ? czr_beta_genesis : czr_live_genesis),
			genesis_amount(std::numeric_limits<czr::uint128_t>::max()),
			burn_account(0)
		{
			CryptoPP::AutoSeededRandomPool random_pool;
			// Randomly generating these mean no two nodes will ever have the same sentinel values which protects against some insecure algorithms
			random_pool.GenerateBlock(not_a_block.bytes.data(), not_a_block.bytes.size());
			random_pool.GenerateBlock(not_an_account.bytes.data(), not_an_account.bytes.size());
		}
		czr::keypair zero_key;
		czr::keypair test_genesis_key;
		czr::account czr_test_account;
		czr::account czr_beta_account;
		czr::account czr_live_account;
		std::string czr_test_genesis;
		std::string czr_beta_genesis;
		std::string czr_live_genesis;
		czr::account genesis_account;
		std::string genesis_block;
		czr::uint128_t genesis_amount;
		czr::block_hash not_a_block;
		czr::account not_an_account;
		czr::account burn_account;
	};
	ledger_constants globals;
}

size_t constexpr czr::block::size;

czr::keypair const & czr::zero_key(globals.zero_key);
czr::keypair const & czr::test_genesis_key(globals.test_genesis_key);
czr::account const & czr::czr_test_account(globals.czr_test_account);
czr::account const & czr::czr_beta_account(globals.czr_beta_account);
czr::account const & czr::czr_live_account(globals.czr_live_account);
std::string const & czr::czr_test_genesis(globals.czr_test_genesis);
std::string const & czr::czr_beta_genesis(globals.czr_beta_genesis);
std::string const & czr::czr_live_genesis(globals.czr_live_genesis);

czr::account const & czr::genesis_account(globals.genesis_account);
std::string const & czr::genesis_block(globals.genesis_block);
czr::uint128_t const & czr::genesis_amount(globals.genesis_amount);
czr::block_hash const & czr::not_a_block(globals.not_a_block);
czr::block_hash const & czr::not_an_account(globals.not_an_account);
czr::account const & czr::burn_account(globals.burn_account);

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


std::unique_ptr<czr::block> czr::deserialize_block(MDB_val const & val_a)
{
	czr::bufferstream stream(reinterpret_cast<uint8_t const *> (val_a.mv_data), val_a.mv_size);
	return deserialize_block(stream);
}

czr::account_info::account_info() :
	head(0),
	open_block(0),
	balance(0),
	modified(0),
	block_count(0)
{
}

czr::account_info::account_info(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	static_assert (sizeof(head) + sizeof(open_block) + sizeof(balance) + sizeof(modified) + sizeof(block_count) == sizeof(*this), "Class not packed");
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::account_info::account_info(czr::block_hash const & head_a, czr::block_hash const & open_block_a, czr::amount const & balance_a, uint64_t modified_a, uint64_t block_count_a) :
	head(head_a),
	open_block(open_block_a),
	balance(balance_a),
	modified(modified_a),
	block_count(block_count_a)
{
}

void czr::account_info::serialize(czr::stream & stream_a) const
{
	write(stream_a, head.bytes);
	write(stream_a, open_block.bytes);
	write(stream_a, balance.bytes);
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
			error = read(stream_a, balance.bytes);
			if (!error)
			{
				error = read(stream_a, modified);
				if (!error)
				{
					error = read(stream_a, block_count);
				}
			}
		}
	}
	return error;
}

bool czr::account_info::operator== (czr::account_info const & other_a) const
{
	return head == other_a.head && open_block == other_a.open_block && balance == other_a.balance && modified == other_a.modified && block_count == other_a.block_count;
}

bool czr::account_info::operator!= (czr::account_info const & other_a) const
{
	return !(*this == other_a);
}

czr::mdb_val czr::account_info::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::account_info *> (this));
}


czr::pending_info::pending_info() :
	source(0),
	amount(0)
{
}

czr::pending_info::pending_info(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	static_assert (sizeof(source) + sizeof(amount) == sizeof(*this), "Packed class");
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::pending_info::pending_info(czr::account const & source_a, czr::amount const & amount_a) :
	source(source_a),
	amount(amount_a)
{
}

void czr::pending_info::serialize(czr::stream & stream_a) const
{
	czr::write(stream_a, source.bytes);
	czr::write(stream_a, amount.bytes);
}

bool czr::pending_info::deserialize(czr::stream & stream_a)
{
	auto result(czr::read(stream_a, source.bytes));
	if (!result)
	{
		result = czr::read(stream_a, amount.bytes);
	}
	return result;
}

bool czr::pending_info::operator== (czr::pending_info const & other_a) const
{
	return source == other_a.source && amount == other_a.amount;
}

czr::mdb_val czr::pending_info::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::pending_info *> (this));
}

czr::pending_key::pending_key(czr::account const & account_a, czr::block_hash const & hash_a) :
	account(account_a),
	hash(hash_a)
{
}

czr::pending_key::pending_key(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	static_assert (sizeof(account) + sizeof(hash) == sizeof(*this), "Packed class");
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

void czr::pending_key::serialize(czr::stream & stream_a) const
{
	czr::write(stream_a, account.bytes);
	czr::write(stream_a, hash.bytes);
}

bool czr::pending_key::deserialize(czr::stream & stream_a)
{
	auto error(czr::read(stream_a, account.bytes));
	if (!error)
	{
		error = czr::read(stream_a, hash.bytes);
	}
	return error;
}

bool czr::pending_key::operator== (czr::pending_key const & other_a) const
{
	return account == other_a.account && hash == other_a.hash;
}

czr::mdb_val czr::pending_key::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::pending_key *> (this));
}

czr::block_info::block_info() :
	account(0),
	balance(0)
{
}

czr::block_info::block_info(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	static_assert (sizeof(account) + sizeof(balance) == sizeof(*this), "Packed class");
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::block_info::block_info(czr::account const & account_a, czr::amount const & balance_a) :
	account(account_a),
	balance(balance_a)
{
}

void czr::block_info::serialize(czr::stream & stream_a) const
{
	czr::write(stream_a, account.bytes);
	czr::write(stream_a, balance.bytes);
}

bool czr::block_info::deserialize(czr::stream & stream_a)
{
	auto error(czr::read(stream_a, account.bytes));
	if (!error)
	{
		error = czr::read(stream_a, balance.bytes);
	}
	return error;
}

bool czr::block_info::operator== (czr::block_info const & other_a) const
{
	return account == other_a.account && balance == other_a.balance;
}

czr::mdb_val czr::block_info::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::block_info *> (this));
}

czr::genesis::genesis()
{
	boost::property_tree::ptree tree;
	std::stringstream istream(czr::genesis_block);
	boost::property_tree::read_json(istream, tree);
	auto b(czr::deserialize_block_json(tree));
	assert(dynamic_cast<czr::block *> (b.get()) != nullptr);
	block.reset(static_cast<czr::block *> (b.release()));

	state.is_on_main_chain = 1;
	state.main_chain_index = 0;
	state.is_stable = 1;
	state.level = 0;
	state.witnessed_level = 0;
	state.creation_date = std::chrono::system_clock::now();
}

void czr::genesis::initialize(MDB_txn * transaction_a, czr::block_store & store_a) const
{
	auto hash_l(hash());
	assert(store_a.latest_begin(transaction_a) == store_a.latest_end());
	store_a.block_put(transaction_a, hash_l, *block);
	store_a.block_state_put(transaction_a, hash_l, state);
	store_a.account_put(transaction_a, genesis_account, { hash_l, block->hash(), std::numeric_limits<czr::uint128_t>::max(), czr::seconds_since_epoch(), 1 });
	store_a.checksum_put(transaction_a, 0, 0, hash_l);
}

czr::block_hash czr::genesis::hash() const
{
	return block->hash();
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

czr::uint256_union czr::witness_list_info::hash()
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

bool czr::witness_list_info::is_compatible(witness_list_info const & other_a)
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

bool czr::witness_list_info::contains(czr::account const & account_a)
{
	auto iter = std::find(witness_list.begin(), witness_list.end(), account_a);
	return iter != witness_list.end();
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
