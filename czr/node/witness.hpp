#pragma once

#include "czr/node/node.hpp"

namespace czr
{
	class witness :public std::enable_shared_from_this<czr::witness>
	{
	public:
		witness(czr::error_message & error_msg, czr::node & node_a, std::string const & account_text, std::string const & password_a);
		void check_and_witness();

	private:
		void do_witness();
		void do_witness_before_threshold();
		bool is_my_block_without_mci(MDB_txn * transaction_a);

		czr::node & node;
		czr::ledger & ledger;
		czr::account account;

		static std::atomic_flag is_witnessing;
		static uint32_t const max_do_witness_interval;
		static uint64_t const threshold_distance;
	};
}