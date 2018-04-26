#pragma once

#include <czr/lib/blocks.hpp>
#include <czr/node/utility.hpp>

#include <boost/property_tree/ptree.hpp>

#include <unordered_map>

#include <blake2/blake2.h>

namespace boost
{
	template <>
	struct hash<czr::uint256_union>
	{
		size_t operator() (czr::uint256_union const & value_a) const
		{
			std::hash<czr::uint256_union> hash;
			return hash(value_a);
		}
	};
}
namespace czr
{
	class block_store;

	/**
	* A key pair. The private key is generated from the random pool, or passed in
	* as a hex string. The public key is derived using ed25519.
	*/
	class keypair
	{
	public:
		keypair();
		keypair(std::string const &);
		czr::public_key pub;
		czr::raw_key prv;
	};

	std::unique_ptr<czr::block> deserialize_block(MDB_val const &);

	/**
	* Latest information about an account
	*/
	class account_info
	{
	public:
		account_info();
		account_info(MDB_val const &);
		account_info(czr::account_info const &) = default;
		account_info(czr::block_hash const &, czr::block_hash const &, czr::amount const &, uint64_t, uint64_t);
		void serialize(czr::stream &) const;
		bool deserialize(czr::stream &);
		bool operator== (czr::account_info const &) const;
		bool operator!= (czr::account_info const &) const;
		czr::mdb_val val() const;
		czr::block_hash head;
		czr::block_hash open_block;
		czr::amount balance;
		/** Seconds since posix epoch */
		uint64_t modified;
		uint64_t block_count;
	};

	/**
	* Information on an uncollected send, source account, amount, target account.
	*/
	class pending_info
	{
	public:
		pending_info();
		pending_info(MDB_val const &);
		pending_info(czr::account const &, czr::amount const &);
		void serialize(czr::stream &) const;
		bool deserialize(czr::stream &);
		bool operator== (czr::pending_info const &) const;
		czr::mdb_val val() const;
		czr::account source;
		czr::amount amount;
	};
	class pending_key
	{
	public:
		pending_key(czr::account const &, czr::block_hash const &);
		pending_key(MDB_val const &);
		void serialize(czr::stream &) const;
		bool deserialize(czr::stream &);
		bool operator== (czr::pending_key const &) const;
		czr::mdb_val val() const;
		czr::account account;
		czr::block_hash hash;
	};
	class block_info
	{
	public:
		block_info();
		block_info(MDB_val const &);
		block_info(czr::account const &, czr::amount const &);
		void serialize(czr::stream &) const;
		bool deserialize(czr::stream &);
		bool operator== (czr::block_info const &) const;
		czr::mdb_val val() const;
		czr::account account;
		czr::amount balance;
	};

	class witness_list_info
	{
	public:
		witness_list_info();
		witness_list_info(MDB_val const &);
		witness_list_info(std::vector<czr::account> const &);
		czr::mdb_val val() const;
		czr::uint256_union hash();
		bool is_compatible(witness_list_info const &);
		bool contains(czr::account const &);
		std::vector<czr::account> witness_list;
	};
	class free_key
	{
	public:
		free_key(uint64_t const &, uint64_t const &, czr::block_hash const &);
		free_key(MDB_val const &);
		bool operator== (czr::free_key const &) const;
		czr::mdb_val val() const;
		uint64_t witnessed_level_desc;
		uint64_t level_asc;
		czr::block_hash hash_asc;
	};

	class block_state
	{
	public:
		block_state();
		block_state(MDB_val const &);
		czr::mdb_val val() const;
		bool is_fork;
		bool is_stable;
		bool is_on_main_chain;
		boost::optional<uint64_t> main_chain_index;
		boost::optional<uint64_t> latest_included_mc_index;
		uint64_t level;
		uint64_t witnessed_level;
		czr::block_hash best_parent;
		std::chrono::system_clock::time_point creation_date;
	};

	enum class process_result
	{
		progress, // Hasn't been seen before, signed correctly
		bad_signature, // Signature was bad, forged or transmission error
		old, // Already seen and was valid
		negative_spend, // Malicious attempt to spend a negative amount
		unreceivable, // Source block doesn't exist or has already been received
		gap_previous, // Block marked as previous is unknown
		gap_source, // Block marked as source is unknown
		not_receive_from_send, // Receive does not have a send source
		account_mismatch, // Account number in open block doesn't match send destination
		opened_burn_account, // The impossible happened, someone found the private key associated with the public key '0'.
		balance_mismatch, // Balance and amount delta don't match
		block_position, // This block cannot follow the previous block
	};
	class process_return
	{
	public:
		czr::process_result code;
		czr::account account;
		czr::amount amount;
		czr::account pending_account;
		boost::optional<bool> is_send;
		bool is_fork;
		uint64_t block_count;
	};
	extern czr::keypair const & zero_key;
	extern czr::keypair const & test_genesis_key;
	extern czr::account const & czr_test_account;
	extern czr::account const & czr_beta_account;
	extern czr::account const & czr_live_account;
	extern std::string const & czr_test_genesis;
	extern std::string const & czr_beta_genesis;
	extern std::string const & czr_live_genesis;
	extern std::string const & genesis_block;
	extern czr::account const & genesis_account;
	extern czr::account const & burn_account;
	extern czr::uint128_t const & genesis_amount;
	// A block hash that compares inequal to any real block hash
	extern czr::block_hash const & not_a_block;
	// An account number that compares inequal to any real account number
	extern czr::block_hash const & not_an_account;
	class genesis
	{
	public:
		explicit genesis();
		void initialize(MDB_txn *, czr::block_store &) const;
		czr::block_hash hash() const;
		std::unique_ptr<czr::block> block;
		czr::block_state state;
	};
}
