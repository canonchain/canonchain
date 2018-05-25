#include <czr/node/witness.hpp>
#include <czr/node/common.hpp>


czr::witness::witness(czr::error_message & error_msg, czr::node & node_a, std::string const & wallet_text, std::string const & account_text):
	node(node_a),
	ledger(node_a.ledger)
{
	czr::uint256_union wallet_key;
	bool error(wallet_key.decode_hex(wallet_text));
	if (error)
	{
		error_msg.error = true;
		error_msg.message = "Bad wallet number";
		return;
	}

	auto existing(node.wallets.items.find(wallet_key));
	error = existing == node.wallets.items.end();
	if (error)
	{
		error_msg.error = true;
		error_msg.message = "Wallet not found";
		return;
	}

	wallet = existing->second;

	error = account.decode_account(account_text);
	if (error)
	{
		error_msg.error = true;
		error_msg.message = "Bad account";
		return;
	}
}

//todo:triggered when non-sync new block message coming
void czr::witness::check_and_witness()
{
	if (is_witnessing.test_and_set())
		return;

	czr::transaction transaction(ledger.store.environment, nullptr, false);
	if(is_my_block_without_mci(transaction))
	{
		is_witnessing.clear();
		BOOST_LOG(node.log) << "My block without mci";
		return;
	}

	// max_mci
	uint64_t max_mci(0);
	czr::store_iterator mc_iter(ledger.store.main_chain_rbegin(transaction));
	if(mc_iter != czr::store_iterator(nullptr))
		max_mci = mc_iter->first.uint64();

	//max_my_mci
	uint64_t max_my_mci(0);
	czr::account_info info;
	bool exists(!ledger.store.account_get(transaction, account, info));
	if (exists)
	{
		czr::block_state head_state;
		bool head_state_error(ledger.store.block_state_get(transaction, info.head, head_state));
		assert(!head_state_error);

		max_my_mci = *head_state.main_chain_index;
	}

	if (max_my_mci == 0)
		max_my_mci = -threshold_distance - 1;

	uint64_t distance = max_mci - max_my_mci;
	if (distance > threshold_distance)
	{
		auto this_l(shared_from_this());
		std::chrono::milliseconds random_period(random_pool.GenerateWord32(0, max_do_witness_interval));
		node.alarm.add(std::chrono::steady_clock::now() + random_period, [this_l]() {
			this_l->do_witness();
		});
	}
	else
	{
		czr::witness_list_info my_wl_info;
		bool exists(!ledger.store.my_witness_list_get(transaction, my_wl_info));
		if (!exists)
		{
			BOOST_LOG(node.log) << "Witness error: My witness list is empty";
			return;
		}

		//if exists unstable non-witness block
		bool has_unstable_non_witness_block;
		for (czr::store_iterator i(ledger.store.unstable_begin(transaction)), n(nullptr); i != n; ++i)
		{
			czr::block_hash u_hash(i->first.uint256());
			auto u_block(ledger.store.block_get(transaction, u_hash));
			assert(u_block != nullptr);

			if (!my_wl_info.contains(u_block->hashables.from))
			{
				has_unstable_non_witness_block = true;
				break;
			}
		}

		if(has_unstable_non_witness_block)
		{
			is_witnessing.clear();
			auto this_l(shared_from_this());
			auto distance_to_threshold(threshold_distance - distance);
			std::chrono::milliseconds random_period(distance_to_threshold * 10000 + random_pool.GenerateWord32(0, 10000));
			node.alarm.add(std::chrono::steady_clock::now() + random_period, [this_l]() {
				this_l->do_witness_before_threshold();
			});
		}
	}
}

void czr::witness::do_witness()
{
	auto from(account);
	auto to(account);
	uint128_t amount(0);
	std::vector<uint8_t> data;

	auto this_l(shared_from_this());
	auto node_l(node.shared());
	wallet->send_async(from, to, amount, data, [this_l, node_l](czr::send_result result) {
		switch (result.code)
		{
		case czr::send_result_codes::ok:
			break;
		case czr::send_result_codes::account_locked:
			BOOST_LOG(node_l->log) << "Witness error: Account locked";
			break;
		case czr::send_result_codes::insufficient_balance:
			BOOST_LOG(node_l->log) << "Witness error: Insufficient balance";
			break;
		case czr::send_result_codes::data_size_too_large:
			BOOST_LOG(node_l->log) << "Witness error: Data size to large";
			break;
		case czr::send_result_codes::validate_error:
			BOOST_LOG(node_l->log) << "Witness error: Validate error";

			//wait some seconds and retry
			std::chrono::milliseconds random_period(random_pool.GenerateWord32(0, max_do_witness_interval));
			node_l->alarm.add(std::chrono::steady_clock::now() + random_period, [this_l]() {
				this_l->do_witness();
			});

			break;
		case czr::send_result_codes::error:
			BOOST_LOG(node_l->log) << "Witness error: Generate block error";
			break;
		default:
			BOOST_LOG(node_l->log) << "Unknown error";
			break;
		}

		this_l->is_witnessing.clear();

	}, boost::none);
}

void czr::witness::do_witness_before_threshold()
{
	if (is_witnessing.test_and_set())
		return;

	{
		czr::transaction transaction(ledger.store.environment, nullptr, false);
		if (is_my_block_without_mci(transaction))
		{
			is_witnessing.clear();
			return;
		}
	}

	BOOST_LOG(node.log) << "will witness before thresholdi";
	do_witness();
}

bool czr::witness::is_my_block_without_mci(MDB_txn * transaction_a)
{
	czr::account_info info;
	bool exists(!ledger.store.account_get(transaction_a, account, info));
	if (exists)
	{
		czr::block_state state;
		bool state_error(ledger.store.block_state_get(transaction_a, info.head, state));
		assert(!state_error);

		if (!state.main_chain_index)
			return true;
	}
	return false;
}

std::atomic_flag is_witnessing = ATOMIC_FLAG_INIT;
uint64_t const czr::witness::max_do_witness_interval(3000);
uint64_t const czr::witness::threshold_distance(50);

