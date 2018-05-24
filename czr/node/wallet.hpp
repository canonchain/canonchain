#pragma once

#include <czr/blockstore.hpp>
#include <czr/common.hpp>
#include <czr/node/common.hpp>

#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>

namespace czr
{
// The fan spreads a key out over the heap to decrease the likelihood of it being recovered by memory inspection
class fan
{
public:
	fan (czr::uint256_union const &, size_t);
	void value (czr::raw_key &);
	void value_set (czr::raw_key const &);
	std::vector<std::unique_ptr<czr::uint256_union>> values;

private:
	std::mutex mutex;
	void value_get (czr::raw_key &);
};
class wallet_value
{
public:
	wallet_value () = default;
	wallet_value (czr::mdb_val const &);
	wallet_value(czr::uint256_union const & key_a);
	czr::mdb_val val () const;
	czr::private_key key;
};
class node_config;
class kdf
{
public:
	void phs (czr::raw_key &, std::string const &, czr::uint256_union const &);
	std::mutex mutex;
};
enum class key_type
{
	not_a_type,
	unknown,
	adhoc,
	deterministic
};
class wallet_store
{
public:
	wallet_store (bool &, czr::kdf &, czr::transaction &, unsigned, std::string const &);
	wallet_store (bool &, czr::kdf &, czr::transaction &, unsigned, std::string const &, std::string const &);
	std::vector<czr::account> accounts (MDB_txn *);
	void initialize (MDB_txn *, bool &, std::string const &);
	czr::uint256_union check (MDB_txn *);
	bool rekey (MDB_txn *, std::string const &);
	bool valid_password (MDB_txn *);
	bool attempt_password (MDB_txn *, std::string const &);
	void wallet_key (czr::raw_key &, MDB_txn *);
	void seed (czr::raw_key &, MDB_txn *);
	void seed_set (MDB_txn *, czr::raw_key const &);
	czr::key_type key_type (czr::wallet_value const &);
	czr::public_key deterministic_insert (MDB_txn *);
	void deterministic_key (czr::raw_key &, MDB_txn *, uint32_t);
	uint32_t deterministic_index_get (MDB_txn *);
	void deterministic_index_set (MDB_txn *, uint32_t);
	void deterministic_clear (MDB_txn *);
	czr::uint256_union salt (MDB_txn *);
	czr::public_key insert_adhoc (MDB_txn *, czr::raw_key const &);
	void insert_watch (MDB_txn *, czr::public_key const &);
	void erase (MDB_txn *, czr::public_key const &);
	czr::wallet_value entry_get_raw (MDB_txn *, czr::public_key const &);
	void entry_put_raw (MDB_txn *, czr::public_key const &, czr::wallet_value const &);
	bool fetch (MDB_txn *, czr::public_key const &, czr::raw_key &);
	bool exists (MDB_txn *, czr::public_key const &);
	void destroy (MDB_txn *);
	czr::store_iterator find (MDB_txn *, czr::uint256_union const &);
	czr::store_iterator begin (MDB_txn *, czr::uint256_union const &);
	czr::store_iterator begin (MDB_txn *);
	czr::store_iterator end ();
	void derive_key (czr::raw_key &, MDB_txn *, std::string const &);
	void serialize_json (MDB_txn *, std::string &);
	void write_backup (MDB_txn *, boost::filesystem::path const &);
	bool move (MDB_txn *, czr::wallet_store &, std::vector<czr::public_key> const &);
	bool import (MDB_txn *, czr::wallet_store &);
	unsigned version (MDB_txn *);
	void version_put (MDB_txn *, unsigned);
	czr::fan password;
	czr::fan wallet_key_mem;
	static unsigned const version_1;
	static unsigned const version_current;
	static czr::uint256_union const version_special;
	static czr::uint256_union const wallet_key_special;
	static czr::uint256_union const salt_special;
	static czr::uint256_union const check_special;
	static czr::uint256_union const seed_special;
	static czr::uint256_union const deterministic_index_special;
	static int const special_count;
	static unsigned const kdf_full_work = 64 * 1024;
	static unsigned const kdf_test_work = 8;
	static unsigned const kdf_work = czr::czr_network == czr::czr_networks::czr_test_network ? kdf_test_work : kdf_full_work;
	czr::kdf & kdf;
	czr::mdb_env & environment;
	MDB_dbi handle;
	std::recursive_mutex mutex;
};
class node;

enum class send_result_codes
{
	ok,
	account_locked,
	insufficient_balance,
	data_size_too_large,
	validate_error,
	error,
};

class send_result
{
public:
	send_result(czr::send_result_codes const & code_a, std::shared_ptr<czr::block> block_a);
	czr::send_result_codes code;
	std::shared_ptr<czr::block> block;
};

class composer;

// A wallet is a set of account keys encrypted by a common encryption key
class wallet : public std::enable_shared_from_this<czr::wallet>
{
public:
	wallet (bool &, czr::transaction &, czr::node &, std::string const &);
	wallet (bool &, czr::transaction &, czr::node &, std::string const &, std::string const &);
	void enter_initial_password ();
	bool valid_password ();
	bool enter_password (std::string const &);
	void insert_watch (MDB_txn *, czr::public_key const &);
	czr::public_key deterministic_insert(MDB_txn * transaction_a);
	czr::public_key deterministic_insert();
	czr::public_key insert_adhoc(MDB_txn * transaction_a, czr::raw_key const & key_a);
	czr::public_key insert_adhoc(czr::raw_key const & account_a);
	bool exists (czr::public_key const &);
	bool import (std::string const &, std::string const &);
	void serialize (std::string &);
	void send_async(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> const & data_a, std::function<void(czr::send_result)> const & action_a, boost::optional<std::string> id_a);
	czr::send_result send_action(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> data_a, boost::optional<std::string> id_a);
	void init_free_accounts (MDB_txn *);
	/** Changes the wallet seed and returns the first account */
	czr::public_key change_seed (MDB_txn * transaction_a, czr::raw_key const & prv_a);

	std::unordered_set<czr::account> free_accounts;
	std::function<void(bool, bool)> lock_observer;
	czr::wallet_store store;
	czr::node & node;
	std::shared_ptr<czr::composer> composer;
};
// The wallets set is all the wallets a node controls.  A node may contain multiple wallets independently encrypted and operated.
class wallets
{
public:
	wallets (bool &, czr::node &);
	~wallets ();
	std::shared_ptr<czr::wallet> open (czr::uint256_union const &);
	std::shared_ptr<czr::wallet> create (czr::uint256_union const &);
	void destroy (czr::uint256_union const &);
	void do_wallet_actions ();
	void queue_wallet_action (czr::uint128_t const &, std::function<void()> const &);
	bool exists (MDB_txn *, czr::public_key const &);
	void stop ();
	std::function<void(bool)> observer;
	std::unordered_map<czr::uint256_union, std::shared_ptr<czr::wallet>> items;
	std::multimap<czr::uint128_t, std::function<void()>, std::greater<czr::uint128_t>> actions;
	std::mutex mutex;
	std::condition_variable condition;
	czr::kdf kdf;
	MDB_dbi handle;
	MDB_dbi send_action_ids;
	czr::node & node;
	bool stopped;
	std::thread thread;
	static czr::uint128_t const generate_priority;
	static czr::uint128_t const high_priority;
};
}
