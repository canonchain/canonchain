#pragma once

#include <czr/common.hpp>

namespace czr
{
	/**
	* The value produced when iterating with \ref store_iterator
	*/
	class store_entry
	{
	public:
		store_entry();
		void clear();
		store_entry * operator-> ();
		czr::mdb_val first;
		czr::mdb_val second;
	};

	/**
	* Iterates the key/value pairs of a transaction
	*/
	class store_iterator
	{
	public:
		store_iterator(MDB_txn *, MDB_dbi);
		store_iterator(std::nullptr_t);
		store_iterator(MDB_txn *, MDB_dbi, MDB_val const &);
		store_iterator(czr::store_iterator &&);
		store_iterator(czr::store_iterator const &) = delete;
		~store_iterator();
		czr::store_iterator & operator++ ();
		void next_dup();
		czr::store_iterator & operator= (czr::store_iterator &&);
		czr::store_iterator & operator= (czr::store_iterator const &) = delete;
		czr::store_entry & operator-> ();
		bool operator== (czr::store_iterator const &) const;
		bool operator!= (czr::store_iterator const &) const;
		MDB_cursor * cursor;
		czr::store_entry current;
	};

	/**
	* Manages block storage and iteration
	*/
	class block_store
	{
	public:
		block_store(bool &, boost::filesystem::path const &, int lmdb_max_dbs = 128);

		void block_put_raw(MDB_txn *, MDB_dbi, czr::block_hash const &, MDB_val);
		void block_put(MDB_txn *, czr::block_hash const &, czr::block const &, czr::block_hash const & = czr::block_hash(0));
		MDB_val block_get_raw(MDB_txn *, czr::block_hash const &);
		std::unique_ptr<czr::block> block_get(MDB_txn *, czr::block_hash const &);
		void block_del(MDB_txn *, czr::block_hash const &);
		bool block_exists(MDB_txn *, czr::block_hash const &);
		czr::store_iterator block_begin(MDB_txn * transaction_a, czr::block_hash const & hash_a);
		czr::block_hash block_successor(MDB_txn *, czr::block_hash const &);
		void block_successor_clear(MDB_txn *, czr::block_hash const &);
		std::unique_ptr<czr::block> block_random(MDB_txn *);
		size_t block_count(MDB_txn *);

		void account_put(MDB_txn *, czr::account const &, czr::account_info const &);
		bool account_get(MDB_txn *, czr::account const &, czr::account_info &);
		void account_del(MDB_txn *, czr::account const &);
		bool account_exists(MDB_txn *, czr::account const &);
		czr::store_iterator latest_begin(MDB_txn *, czr::account const &);
		czr::store_iterator latest_begin(MDB_txn *);
		czr::store_iterator latest_end();

		void pending_put(MDB_txn *, czr::pending_key const &, czr::pending_info const &);
		void pending_del(MDB_txn *, czr::pending_key const &);
		bool pending_get(MDB_txn *, czr::pending_key const &, czr::pending_info &);
		bool pending_exists(MDB_txn *, czr::pending_key const &);
		czr::store_iterator pending_begin(MDB_txn *, czr::pending_key const &);
		czr::store_iterator pending_begin(MDB_txn *);
		czr::store_iterator pending_end();

		void unchecked_clear(MDB_txn *);
		void unchecked_put(MDB_txn *, czr::block_hash const &, std::shared_ptr<czr::block> const &);
		std::vector<std::shared_ptr<czr::block>> unchecked_get(MDB_txn *, czr::block_hash const &);
		void unchecked_del(MDB_txn *, czr::block_hash const &, czr::block const &);
		czr::store_iterator unchecked_begin(MDB_txn *);
		czr::store_iterator unchecked_begin(MDB_txn *, czr::block_hash const &);
		czr::store_iterator unchecked_end();
		size_t unchecked_count(MDB_txn *);
		std::unordered_multimap<czr::block_hash, std::shared_ptr<czr::block>> unchecked_cache;

		void unsynced_put(MDB_txn *, czr::block_hash const &);
		void unsynced_del(MDB_txn *, czr::block_hash const &);
		bool unsynced_exists(MDB_txn *, czr::block_hash const &);
		czr::store_iterator unsynced_begin(MDB_txn *, czr::block_hash const &);
		czr::store_iterator unsynced_begin(MDB_txn *);
		czr::store_iterator unsynced_end();

		void checksum_put(MDB_txn *, uint64_t, uint8_t, czr::checksum const &);
		bool checksum_get(MDB_txn *, uint64_t, uint8_t, czr::checksum &);
		void checksum_del(MDB_txn *, uint64_t, uint8_t);

		bool summary_get(MDB_txn *, czr::block_hash const &, czr::uint256_union &);
		void summary_put(MDB_txn *, czr::block_hash const &, czr::uint256_union const &);

		bool witnesslisthash_block_get(MDB_txn *, czr::witness_list_hash const &, czr::block_hash &);
		bool witnesslisthash_block_exists(MDB_txn * transaction_a, czr::witness_list_hash const & hash_a);
		void witnesslisthash_block_put(MDB_txn *, czr::witness_list_hash const &, czr::block_hash const &);

		bool block_witnesslist_get(MDB_txn *, czr::block_hash const &, czr::witness_list_info &);
		void block_witnesslist_put(MDB_txn *, czr::block_hash const &, czr::witness_list_info const &);

		void free_put(MDB_txn *, czr::block_hash const &, czr::free_block const &);
		void free_del(MDB_txn *, czr::block_hash const &);

		bool block_state_get(MDB_txn *, czr::block_hash const &, czr::block_state &);
		void block_state_put(MDB_txn *, czr::block_hash const &, czr::block_state const &);

		void flush(MDB_txn *);
		std::mutex cache_mutex;

		void version_put(MDB_txn *, int);
		int version_get(MDB_txn *);

		void clear(MDB_dbi);

		czr::mdb_env environment;
		// block_hash -> account                                        // Maps head blocks to owning account
		MDB_dbi accounts;
		// block_hash -> block
		MDB_dbi blocks;
		// block_hash -> sender, amount, destination                    // Pending blocks to sender account, amount, destination account
		MDB_dbi pending;
		// block_hash -> block                                          // Unchecked bootstrap blocks
		MDB_dbi unchecked;
		// block_hash ->                                                // Blocks that haven't been broadcast
		MDB_dbi unsynced;
		// (uint56_t, uint8_t) -> block_hash                            // Mapping of region to checksum
		MDB_dbi checksum;
		// uint256_union -> ?											// Meta information about block store
		MDB_dbi meta;

		//block hash -> witnesslist
		MDB_dbi block_witnesslist;
		//witnesslist hash -> block hash
		MDB_dbi witnesslisthash_block;
		//block hash -> witnessed level, level
		MDB_dbi free;
		//block hash -> block state
		MDB_dbi block_state;
		// block hash -> summary hash
		MDB_dbi summary;
		//block hash -> skiplist
		MDB_dbi skiplist;
	};
}
