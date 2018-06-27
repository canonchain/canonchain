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
class kdf
{
public:
	void phs (czr::raw_key &, std::string const &, czr::uint256_union const &);
	std::mutex mutex;

	static unsigned const kdf_full_work = 64 * 1024;
	static unsigned const kdf_test_work = 8;
	static unsigned const kdf_work = czr::czr_network == czr::czr_networks::czr_test_network ? kdf_test_work : kdf_full_work;
};
class node;

enum class send_result_codes
{
	ok,
	account_locked,
	from_not_exists,
	wrong_password,
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

class wallet
{
public:
	wallet (bool & error_a, czr::node & node_a);
	~wallet ();
	void send_async(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> const & data_a, std::string const & password_a, std::function<void(czr::send_result)> const & action_a, boost::optional<std::string> id_a);
	czr::send_result send_action(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, std::vector<uint8_t> data_a, std::string const & password_a, boost::optional<std::string> id_a);
	void do_wallet_actions();
	void queue_wallet_action(std::function<void()> const & action_a);
	void stop();

	std::deque<std::function<void()>> actions;
	std::mutex mutex;
	std::condition_variable condition;
	MDB_dbi send_action_ids;
	czr::node & node;
	std::shared_ptr<czr::composer> composer;
	bool stopped;
	std::thread thread;
};

class key_content
{
public:
	key_content();
	key_content(MDB_val const & val_a);
	key_content(bool & error_a, std::string const & json_a);
	key_content(czr::account const & account_a, czr::uint256_union const & kdf_salt_a, czr::uint128_union const & iv_a, czr::secret_key const & ciphertext_a);
	czr::mdb_val val() const;
	std::string to_json() const;

	czr::account account;
	czr::uint256_union kdf_salt;
	czr::uint128_union iv;
	czr::secret_key ciphertext;
};

class key_manager
{
public:
	key_manager(bool & error_a, czr::mdb_env & environment, boost::filesystem::path const & application_path_a);
	bool exists(czr::public_key const & pub_a);
	bool find(czr::public_key const & pub_a, czr::key_content & kc_a);
	std::list<czr::public_key> list();
	czr::public_key create(MDB_txn * transaction_a, std::string const & password_a);
	bool change_password(MDB_txn * transaction_a, czr::public_key const & pub_a, std::string const & old_password_a, std::string const & new_password_a);
	bool remove(MDB_txn * transaction_a, czr::public_key const & pub_a, std::string const & password_a);
	bool import(MDB_txn * transaction_a, std::string const & json_a, key_content & kc_a);
	bool decrypt_prv(czr::public_key const & pub_a, std::string const & password_a, czr::raw_key & prv);
	bool decrypt_prv(czr::key_content const & kc, std::string const & password_a, czr::raw_key & prv);
	bool is_locked(czr::public_key const & pub_a);
	bool find_unlocked_prv(czr::public_key const & pub_a, czr::raw_key & prv);
	bool unlock(czr::public_key const & pub_a, std::string const & password_a);
	void write_backup(czr::public_key const & account, std::string const & json);
	void lock(czr::public_key const & pub_a);

private:
	czr::key_content gen_key_content(czr::raw_key const & prv, std::string const & password_a);
	void add_or_update_key(MDB_txn * transaction_a, czr::key_content const & kc);
	bool key_get(MDB_txn * transaction_a, czr::public_key const & pub_a, czr::key_content & value_a);
	void key_put(MDB_txn * transaction_a, czr::public_key const & pub_a, czr::key_content const & content_a);
	void key_del(MDB_txn * transaction_a, czr::public_key const & pub_a);

	czr::kdf kdf;
	MDB_dbi keys;
	boost::filesystem::path backup_path;

	std::unordered_map<czr::public_key, czr::key_content> key_contents;
	std::mutex key_contents_mutex;

	//todo: to use fan for security
	std::unordered_map<czr::public_key, czr::private_key> unlocked;
	std::mutex unlocked_mutex;
};
}
