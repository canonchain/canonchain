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
		czr::account account(MDB_txn *, czr::block_hash const &);
		czr::uint128_t block_balance(MDB_txn *, czr::block_hash const &);
		czr::uint128_t block_amount(MDB_txn *, czr::block const &);
		czr::uint128_t account_balance(MDB_txn *, czr::account const &);
		czr::uint128_t account_pending(MDB_txn *, czr::account const &);
		std::unique_ptr<czr::block> successor(MDB_txn *, czr::block_hash const &);
		czr::block_hash latest(MDB_txn *, czr::account const &);
		czr::block_hash latest_root(MDB_txn *, czr::account const &);
		bool block_exists(czr::block_hash const &);
		std::string block_text(char const *);
		std::string block_text(czr::block_hash const &);
		bool is_send(MDB_txn *, czr::block const &);
		czr::block_hash block_destination(MDB_txn *, czr::block const &);
		czr::block_hash block_source(MDB_txn *, czr::block const &);
		czr::process_return process(MDB_txn *, czr::block const &);
		void rollback(MDB_txn *, czr::block_hash const &);
		void change_latest(MDB_txn *, czr::account const &, czr::block_hash const &, czr::amount const &, uint64_t);
		void checksum_update(MDB_txn *, czr::block_hash const &);
		czr::checksum checksum(MDB_txn *, czr::account const &, czr::account const &);
		void dump_account_chain(czr::account const &);
		static czr::uint128_t const unit;
		czr::block_store & store;
	};
};
