#pragma once

#include <czr/common.hpp>

namespace czr
{
	class block_store;

	class shared_ptr_block_hash
	{
	public:
		size_t operator() (std::shared_ptr<czr::block> const &) const;
		bool operator() (std::shared_ptr<czr::block> const &, std::shared_ptr<czr::block> const &) const;
	};

	class ledger
	{
	public:
		ledger(czr::block_store &);
		czr::account block_account(MDB_txn *, czr::block_hash const &);
		czr::uint128_t account_balance(MDB_txn *, czr::account const &);
		std::unique_ptr<czr::block> successor(MDB_txn *, czr::block_hash const &);
		czr::witness_list_info block_witness_list(MDB_txn * transaction_a, czr::block const & block_a);
		czr::block_hash latest(MDB_txn *, czr::account const &);
		czr::block_hash latest_root(MDB_txn *, czr::account const &);
		bool block_exists(czr::block_hash const &);
		void change_account_latest(MDB_txn *, czr::account const &, czr::block_hash const &, uint64_t const &);
		void try_set_account_good_stable_mci(MDB_txn * transaction_a, czr::account const & account_a, uint64_t good_stable_mci);
		void checksum_update(MDB_txn *, czr::block_hash const &);
		czr::checksum checksum(MDB_txn *, czr::account const &, czr::account const &);
		void dump_account_chain(czr::account const &);
		static czr::uint128_t const unit;
		czr::block_store & store;
	};
};
