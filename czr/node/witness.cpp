#include <czr/node/witness.hpp>
#include <czr/node/common.hpp>


czr::witness::witness(czr::error_message & error_msg, czr::node & node_a, std::string const & wallet_text, std::string const & account_text):
	node(node_a)
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

void czr::witness::start()
{
	ongoing_send();
}

void czr::witness::ongoing_send()
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

			std::chrono::seconds period(3);
			node_l->alarm.add(std::chrono::steady_clock::now() + period, [this_l]() {
				this_l->ongoing_send();
			});

			break;
		case czr::send_result_codes::account_locked:
			BOOST_LOG(node_l->log) << "Account locked";
			break;
		case czr::send_result_codes::insufficient_balance:
			BOOST_LOG(node_l->log) << "Insufficient balance";
			break;
		case czr::send_result_codes::data_size_too_large:
			BOOST_LOG(node_l->log) << "Data size to large";
			break;
		case czr::send_result_codes::error:
			BOOST_LOG(node_l->log) << "Generate block error";
			break;
		default:
			BOOST_LOG(node_l->log) << "Unknown error";
			break;
		}
	}, boost::none);
}
