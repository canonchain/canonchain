#pragma once

#include <czr/lib/blocks.hpp>
#include <czr/node/utility.hpp>

#include <unordered_map>
#include <set>

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

	/**
	* Latest information about an account
	*/
	class account_info
	{
	public:
		account_info();
		account_info(MDB_val const &);
		account_info(czr::account_info const &) = default;
		account_info(czr::block_hash const &, czr::block_hash const &, uint64_t, uint64_t);
		void serialize(czr::stream &) const;
		bool deserialize(czr::stream &);
		bool operator== (czr::account_info const &) const;
		bool operator!= (czr::account_info const &) const;
		czr::mdb_val val() const;
		czr::block_hash head;
		czr::block_hash open_block;
		/** Seconds since posix epoch */
		uint64_t modified;
		uint64_t block_count;
		boost::optional<uint64_t> first_good_stable_mci;
	};

	class witness_list_info
	{
	public:
		witness_list_info();
		witness_list_info(MDB_val const &);
		witness_list_info(std::vector<czr::account> const &);
		czr::mdb_val val() const;
		czr::uint256_union hash();
		bool is_compatible(witness_list_info const &) const;
		bool contains(czr::account const &) const;
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
		bool is_fork;	//fork, not to pay fee, need clear content
		bool is_invalid;	//invalid, not to pay fee, need clear content
		bool is_fail;	//fail, pay fee, no need to clear content
		bool is_free;
		bool is_stable;
		bool is_on_main_chain;
		boost::optional<uint64_t> main_chain_index;
		boost::optional<uint64_t> latest_included_mc_index;
		uint64_t level;
		uint64_t witnessed_level;
		czr::block_hash best_parent;
		std::chrono::system_clock::time_point creation_date;
		czr::account_state_hash from_state;
		czr::account_state_hash to_state;
	};

	class block_child_key
	{
	public:
		block_child_key(czr::block_hash const &, czr::block_hash const &);
		block_child_key(MDB_val const &);
		bool operator== (czr::block_child_key const &) const;
		czr::mdb_val val() const;
		czr::block_hash hash;
		czr::block_hash child_hash;
	};

	class account_state
	{
	public:
		account_state();
		account_state(czr::account const & account_a, czr::block_hash const & block_hash_a, czr::account_state_hash const & pervious_a, czr::amount const & balance_a);
		account_state(MDB_val const &);
		czr::mdb_val val() const;
		czr::account_state_hash hash();
		czr::account account;
		czr::block_hash block_hash;
		czr::account_state_hash pervious;
		czr::amount balance;
	};

	class skiplist_info
	{
	public:
		skiplist_info(std::vector<czr::block_hash> const &);
		skiplist_info(MDB_val const &);
		czr::mdb_val val() const;
		std::vector<czr::block_hash> list;
	};

	class summary
	{
	public:
		static czr::summary_hash gen_summary_hash(czr::block_hash const & block_hash,
			std::vector<czr::summary_hash> const & parent_hashs,
			std::set<czr::summary_hash> const & skip_list,
			bool const & is_fork, bool const & is_error, bool const & is_fail,
			czr::account_state_hash const & from_state_hash, czr::account_state_hash const & to_state_hash);
	};

	std::unique_ptr<czr::block> deserialize_block(MDB_val const &);
}
