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

	enum store_iterator_direction
	{
		forward,
		reverse,
	};

	/**
	* Iterates the key/value pairs of a transaction
	*/
	class store_iterator
	{
	public:
		store_iterator(MDB_txn *, MDB_dbi, czr::store_iterator_direction = czr::store_iterator_direction::forward);
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
		czr::store_iterator_direction direction = czr::store_iterator_direction::forward;
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
		bool block_exists(MDB_txn *, czr::block_hash const &);
		czr::store_iterator block_begin(MDB_txn *, czr::block_hash const &);
		void block_predecessor_set(MDB_txn *, czr::block const &, bool const &);
		czr::block_hash block_successor(MDB_txn *, czr::block_hash const &);
		void block_successor_clear(MDB_txn *, czr::block_hash const &);
		std::unique_ptr<czr::block> block_random(MDB_txn *);
		size_t block_count(MDB_txn *);

		bool account_state_get(MDB_txn * transaction_a, czr::account_state_hash const & hash_a, czr::account_state & value_a);
		void account_state_put(MDB_txn * transaction_a, czr::account_state_hash const & hash_a, czr::account_state const & value_a);

		bool latest_account_state_get(MDB_txn * transaction_a, czr::account const & account_a, czr::account_state & value_a);
		void latest_account_state_put(MDB_txn * transaction_a, czr::account const & account_a, czr::account_state const & value_a);

		void account_put(MDB_txn *, czr::account const &, czr::account_info const &);
		bool account_get(MDB_txn *, czr::account const &, czr::account_info &);
		void account_del(MDB_txn *, czr::account const &);
		bool account_exists(MDB_txn *, czr::account const &);
		czr::store_iterator account_begin(MDB_txn *, czr::account const &);
		czr::store_iterator account_begin(MDB_txn *);
		czr::store_iterator account_end();

		void unchecked_clear(MDB_txn *);
		void unchecked_put(MDB_txn *, czr::block_hash const &, std::shared_ptr<czr::block> const &);
		std::vector<std::shared_ptr<czr::block>> unchecked_get(MDB_txn *, czr::block_hash const &);
		void unchecked_del(MDB_txn *, czr::block_hash const &, czr::block const &);
		czr::store_iterator unchecked_begin(MDB_txn *);
		czr::store_iterator unchecked_begin(MDB_txn *, czr::block_hash const &);
		czr::store_iterator unchecked_end();
		size_t unchecked_count(MDB_txn *);
		std::unordered_multimap<czr::block_hash, std::shared_ptr<czr::block>> unchecked_cache;

		bool block_summary_get(MDB_txn *, czr::block_hash const &, czr::summary_hash &);
		void block_summary_put(MDB_txn *, czr::block_hash const &, czr::summary_hash const &);

		bool summary_block_get(MDB_txn *, czr::summary_hash const &, czr::block_hash &);
		void summary_block_put(MDB_txn *, czr::summary_hash const &, czr::block_hash const &);

		bool witness_list_hash_block_get(MDB_txn * transaction_a, czr::witness_list_key const & key_a, czr::block_hash & block_a);
		czr::store_iterator witness_list_hash_block_begin(MDB_txn * transaction_a, czr::witness_list_key const & key_a);
		bool witness_list_hash_block_exists(MDB_txn * transaction_a, czr::witness_list_key const & key_a);
		void witness_list_hash_block_put(MDB_txn * transaction_a, czr::witness_list_key const & key_a, czr::block_hash const & block_a);

		bool block_witness_list_get(MDB_txn *, czr::block_hash const &, czr::witness_list_info &);
		void block_witness_list_put(MDB_txn *, czr::block_hash const &, czr::witness_list_info const &);

		czr::store_iterator free_begin(MDB_txn *);
		void free_put(MDB_txn *, czr::free_key const &);
		void free_del(MDB_txn *, czr::free_key const &);

		czr::store_iterator unstable_begin(MDB_txn *);
		void unstable_put(MDB_txn *, czr::block_hash const &);
		void unstable_del(MDB_txn *, czr::block_hash const &);

		bool block_state_get(MDB_txn *, czr::block_hash const &, czr::block_state &);
		void block_state_put(MDB_txn *, czr::block_hash const &, czr::block_state const &);

		bool main_chain_get(MDB_txn *, uint64_t const &, czr::block_hash &);
		czr::store_iterator main_chain_begin(MDB_txn *, uint64_t const &);
		czr::store_iterator main_chain_rbegin(MDB_txn *);
		void main_chain_put(MDB_txn *, uint64_t const &, czr::block_hash const &);
		void main_chain_del(MDB_txn *, uint64_t const &);

		czr::store_iterator mci_block_beign(MDB_txn * transaction_a, czr::mci_block_key const & key);
		czr::store_iterator mci_block_rbeign(MDB_txn * transaction_a);
		void mci_block_put(MDB_txn * transaction_a, czr::mci_block_key const & key);
		void mci_block_del(MDB_txn * transaction_a, czr::mci_block_key const & key);

		//unhandled_dependency
		void unhandled_dependency_get(MDB_txn * transaction_a, czr::block_hash const &unhandle_a,std::list<czr::block_hash>& dependency_list_a);
		bool unhandled_dependency_exists(MDB_txn * transaction_a, czr::block_hash const &unhandle_a);
		void unhandled_dependency_put(MDB_txn * transaction_a, czr::block_hash const &unhandle_a, czr::block_hash const &dependency_a);
		void unhandled_dependency_del(MDB_txn * transaction_a, czr::block_hash const &unhandle_a, czr::block_hash const &dependency_a);

		void dependency_unhandled_get(MDB_txn * transaction_a, czr::block_hash const &dependency_a, std::list<czr::block_hash>& unhandled_list_a);
		void dependency_unhandled_put(MDB_txn * transaction_a, czr::block_hash const &dependency_a, czr::block_hash const &unhandle_a);
		void dependency_unhandled_del(MDB_txn * transaction_a, czr::block_hash const &dependency_a, czr::block_hash const &unhandle_a);

		void last_stable_mci_put(MDB_txn * transaction_a, uint64_t const & last_stable_mci_value);
		uint64_t last_stable_mci_get(MDB_txn *);

		czr::store_iterator block_child_begin(MDB_txn * transaction_a, czr::block_child_key const & key_a);
		void block_child_put(MDB_txn * transaction_a, czr::block_child_key const & key_a);

		bool skiplist_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::skiplist_info & skiplist);
		void skiplist_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, czr::skiplist_info const & skiplist);

		bool fork_successor_get(MDB_txn *, czr::block_hash const &, czr::block_hash &);
		void fork_successor_put(MDB_txn *, czr::block_hash const &, czr::block_hash const &);
		void fork_successor_del(MDB_txn *, czr::block_hash const &);

		bool genesis_hash_get(MDB_txn * transaction_a, czr::block_hash & genesis_hash);
		void genesis_hash_put(MDB_txn * transaction_a, czr::block_hash const & genesis_hash);

		bool my_witness_list_get(MDB_txn * transaction_a, czr::witness_list_info & my_wl_info);
		void my_witness_list_put(MDB_txn * transaction_a, czr::witness_list_info my_wl_info);

		bool unhandled_get(MDB_txn * transaction_a, czr::block_hash const & hash_a, dev::bytes & rlp);
		void unhandled_put(MDB_txn * transaction_a, czr::block_hash const & hash_a, dev::bytes & rlp);
		void unhandled_del(MDB_txn * transaction_a, czr::block_hash const & hash_a);

		void flush(MDB_txn *);
		std::mutex cache_mutex;

		void version_put(MDB_txn *, int);
		int version_get(MDB_txn *);

		void clear(MDB_dbi);

		czr::mdb_env environment;
		// block_hash -> account                                        // Maps head blocks to owning account
		MDB_dbi account_info;
		//account state hash -> account state
		MDB_dbi account_state;
		//account -> latest account state
		MDB_dbi latest_account_state;
		// block_hash -> block
		MDB_dbi blocks;
		// block_hash -> block                                          // Unchecked bootstrap blocks
		MDB_dbi unchecked;
		// uint256_union -> ?											// Meta information about block store
		MDB_dbi meta;

		//block hash -> witness_list
		MDB_dbi block_witness_list;
		//witness_list hash -> block hash
		MDB_dbi witness_list_hash_block;
		//block hash -> block state
		MDB_dbi block_state;
		//block hash , child block hash -> nullptr
		MDB_dbi block_child;

		//witnessed level, level, block hash -> nullptr
		MDB_dbi free;
		//block hash -> nullptr
		MDB_dbi unstable;
		//main chain index -> block hash
		MDB_dbi main_chain;
		//main chain index, block hash -> nullptr
		MDB_dbi mci_block;
		// block hash -> summary hash
		MDB_dbi block_summary;
		// summary hash -> block hash
		MDB_dbi summary_block;
		//block hash -> skiplist
		MDB_dbi skiplist;
		//pervious block hash -> block hash
		MDB_dbi fork_successor;
		//joint block hash -> joint
		MDB_dbi unhandled;
		MDB_dbi unhandled_dependency;
		MDB_dbi dependency_unhandled;
		//key -> value
		MDB_dbi prop;



		//genesis hash key
		static czr::uint256_union const genesis_hash_key;
		//last statble main chain index key
		static czr::uint256_union const last_stable_mci_key;
		//my witness list key
		static czr::uint256_union const my_witness_list_key;
};
}
