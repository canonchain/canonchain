#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <czr/node/rpc.hpp>

#include <czr/node/node.hpp>

#include <ed25519-donna/ed25519.h>

#ifdef CANONCHAIN_SECURE_RPC
#include <czr/node/rpc_secure.hpp>
#endif

czr::rpc_secure_config::rpc_secure_config() :
	enable(false),
	verbose_logging(false)
{
}

void czr::rpc_secure_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("enable", enable);
	tree_a.put("verbose_logging", verbose_logging);
	tree_a.put("server_key_passphrase", server_key_passphrase);
	tree_a.put("server_cert_path", server_cert_path);
	tree_a.put("server_key_path", server_key_path);
	tree_a.put("server_dh_path", server_dh_path);
	tree_a.put("client_certs_path", client_certs_path);
}

bool czr::rpc_secure_config::deserialize_json(boost::property_tree::ptree const & tree_a)
{
	auto error(false);
	try
	{
		enable = tree_a.get<bool>("enable");
		verbose_logging = tree_a.get<bool>("verbose_logging");
		server_key_passphrase = tree_a.get<std::string>("server_key_passphrase");
		server_cert_path = tree_a.get<std::string>("server_cert_path");
		server_key_path = tree_a.get<std::string>("server_key_path");
		server_dh_path = tree_a.get<std::string>("server_dh_path");
		client_certs_path = tree_a.get<std::string>("client_certs_path");
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

czr::rpc_config::rpc_config() :
	address(boost::asio::ip::address_v6::loopback()),
	port(czr::rpc::rpc_port),
	enable_control(false),
	frontier_request_limit(16384),
	chain_request_limit(16384)
{
}

czr::rpc_config::rpc_config(bool enable_control_a) :
	address(boost::asio::ip::address_v6::loopback()),
	port(czr::rpc::rpc_port),
	enable_control(enable_control_a),
	frontier_request_limit(16384),
	chain_request_limit(16384)
{
}

void czr::rpc_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("address", address.to_string());
	tree_a.put("port", std::to_string(port));
	tree_a.put("enable_control", enable_control);
	tree_a.put("frontier_request_limit", frontier_request_limit);
	tree_a.put("chain_request_limit", chain_request_limit);
}

bool czr::rpc_config::deserialize_json(boost::property_tree::ptree const & tree_a)
{
	auto result(false);
	try
	{
		auto rpc_secure_l(tree_a.get_child_optional("secure"));
		if (rpc_secure_l)
		{
			result = secure.deserialize_json(rpc_secure_l.get());
		}

		if (!result)
		{
			auto address_l(tree_a.get<std::string>("address"));
			auto port_l(tree_a.get<std::string>("port"));
			enable_control = tree_a.get<bool>("enable_control");
			auto frontier_request_limit_l(tree_a.get<std::string>("frontier_request_limit"));
			auto chain_request_limit_l(tree_a.get<std::string>("chain_request_limit"));
			try
			{
				port = std::stoul(port_l);
				result = port > std::numeric_limits<uint16_t>::max();
				frontier_request_limit = std::stoull(frontier_request_limit_l);
				chain_request_limit = std::stoull(chain_request_limit_l);
			}
			catch (std::logic_error const &)
			{
				result = true;
			}
			boost::system::error_code ec;
			address = boost::asio::ip::address_v6::from_string(address_l, ec);
			if (ec)
			{
				result = true;
			}
		}
	}
	catch (std::runtime_error const &)
	{
		result = true;
	}
	return result;
}

czr::rpc::rpc(boost::asio::io_service & service_a, czr::node & node_a, czr::rpc_config const & config_a) :
	acceptor(service_a),
	config(config_a),
	node(node_a)
{
}

void czr::rpc::start()
{
	auto endpoint(czr::tcp_endpoint(config.address, config.port));
	acceptor.open(endpoint.protocol());
	acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

	boost::system::error_code ec;
	acceptor.bind(endpoint, ec);
	if (ec)
	{
		BOOST_LOG(node.log) << boost::str(boost::format("Error while binding for RPC on port %1%: %2%") % endpoint.port() % ec.message());
		throw std::runtime_error(ec.message());
	}

	acceptor.listen();

	accept();
}

void czr::rpc::accept()
{
	auto connection(std::make_shared<czr::rpc_connection>(node, *this));
	acceptor.async_accept(connection->socket, [this, connection](boost::system::error_code const & ec) {
		if (!ec)
		{
			accept();
			connection->parse_connection();
		}
		else
		{
			BOOST_LOG(this->node.log) << boost::str(boost::format("Error accepting RPC connections: %1%") % ec);
		}
	});
}

void czr::rpc::stop()
{
	acceptor.close();
}

czr::rpc_handler::rpc_handler(czr::node & node_a, czr::rpc & rpc_a, std::string const & body_a, std::function<void(boost::property_tree::ptree const &)> const & response_a) :
	body(body_a),
	node(node_a),
	rpc(rpc_a),
	response(response_a)
{
}

void czr::error_response(std::function<void(boost::property_tree::ptree const &)> response_a, std::string const & message_a)
{
	boost::property_tree::ptree response_l;
	response_l.put("error", message_a);
	response_a(response_l);
}

namespace
{
	bool decode_unsigned(std::string const & text, uint64_t & number)
	{
		bool result;
		size_t end;
		try
		{
			number = std::stoull(text, &end);
			result = false;
		}
		catch (std::invalid_argument const &)
		{
			result = true;
		}
		catch (std::out_of_range const &)
		{
			result = true;
		}
		result = result || end != text.size();
		return result;
	}
}

void czr::rpc_handler::account_balance()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		auto balance(node.balance_pending(account));
		boost::property_tree::ptree response_l;
		response_l.put("balance", balance.first.convert_to<std::string>());
		response_l.put("pending", balance.second.convert_to<std::string>());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::account_block_count()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		czr::transaction transaction(node.store.environment, nullptr, false);
		czr::account_info info;
		if (!node.store.account_get(transaction, account, info))
		{
			boost::property_tree::ptree response_l;
			response_l.put("block_count", std::to_string(info.block_count));
			response(response_l);
		}
		else
		{
			error_response(response, "Account not found");
		}
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::account_create()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				const bool generate_work = request.get<bool>("work", true);
				czr::account new_key(existing->second->deterministic_insert(generate_work));
				if (!new_key.is_zero())
				{
					boost::property_tree::ptree response_l;
					response_l.put("account", new_key.to_account());
					response(response_l);
				}
				else
				{
					error_response(response, "Wallet is locked");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_get()
{
	std::string key_text(request.get<std::string>("key"));
	czr::uint256_union pub;
	auto error(pub.decode_hex(key_text));
	if (!error)
	{
		boost::property_tree::ptree response_l;
		response_l.put("account", pub.to_account());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad public key");
	}
}

void czr::rpc_handler::account_info()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		const bool pending = request.get<bool>("pending", false);
		czr::transaction transaction(node.store.environment, nullptr, false);
		czr::account_info info;
		if (!node.store.account_get(transaction, account, info))
		{
			boost::property_tree::ptree response_l;
			response_l.put("frontier", info.head.to_string());
			response_l.put("open_block", info.open_block.to_string());
			std::string balance;
			czr::uint128_union(info.balance).encode_dec(balance);
			response_l.put("balance", balance);
			response_l.put("modified_timestamp", std::to_string(info.modified));
			response_l.put("block_count", std::to_string(info.block_count));
			if (pending)
			{
				auto account_pending(node.ledger.account_pending(transaction, account));
				response_l.put("pending", account_pending.convert_to<std::string>());
			}
			response(response_l);
		}
		else
		{
			error_response(response, "Account not found");
		}
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::account_key()
{
	std::string account_text(request.get<std::string>("account"));
	czr::account account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		boost::property_tree::ptree response_l;
		response_l.put("key", account.to_string());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::account_list()
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			boost::property_tree::ptree response_l;
			boost::property_tree::ptree accounts;
			czr::transaction transaction(node.store.environment, nullptr, false);
			for (auto i(existing->second->store.begin(transaction)), j(existing->second->store.end()); i != j; ++i)
			{
				boost::property_tree::ptree entry;
				entry.put("", czr::uint256_union(i->first.uint256()).to_account());
				accounts.push_back(std::make_pair("", entry));
			}
			response_l.add_child("accounts", accounts);
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad wallet number");
	}
}

void czr::rpc_handler::account_move()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		std::string source_text(request.get<std::string>("source"));
		auto accounts_text(request.get_child("accounts"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				auto wallet(existing->second);
				czr::uint256_union source;
				auto error(source.decode_hex(source_text));
				if (!error)
				{
					auto existing(node.wallets.items.find(source));
					if (existing != node.wallets.items.end())
					{
						auto source(existing->second);
						std::vector<czr::public_key> accounts;
						for (auto i(accounts_text.begin()), n(accounts_text.end()); i != n; ++i)
						{
							czr::public_key account;
							account.decode_hex(i->second.get<std::string>(""));
							accounts.push_back(account);
						}
						czr::transaction transaction(node.store.environment, nullptr, true);
						auto error(wallet->store.move(transaction, source->store, accounts));
						boost::property_tree::ptree response_l;
						response_l.put("moved", error ? "0" : "1");
						response(response_l);
					}
					else
					{
						error_response(response, "Source not found");
					}
				}
				else
				{
					error_response(response, "Bad source number");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_remove()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		std::string account_text(request.get<std::string>("account"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				auto wallet(existing->second);
				czr::transaction transaction(node.store.environment, nullptr, true);
				if (existing->second->store.valid_password(transaction))
				{
					czr::account account_id;
					auto error(account_id.decode_account(account_text));
					if (!error)
					{
						auto account(wallet->store.find(transaction, account_id));
						if (account != wallet->store.end())
						{
							wallet->store.erase(transaction, account_id);
							boost::property_tree::ptree response_l;
							response_l.put("removed", "1");
							response(response_l);
						}
						else
						{
							error_response(response, "Account not found in wallet");
						}
					}
					else
					{
						error_response(response, "Bad account number");
					}
				}
				else
				{
					error_response(response, "Wallet locked");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::accounts_balances()
{
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree balances;
	for (auto & accounts : request.get_child("accounts"))
	{
		std::string account_text = accounts.second.data();
		czr::uint256_union account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			boost::property_tree::ptree entry;
			auto balance(node.balance_pending(account));
			entry.put("balance", balance.first.convert_to<std::string>());
			entry.put("pending", balance.second.convert_to<std::string>());
			balances.push_back(std::make_pair(account.to_account(), entry));
		}
		else
		{
			error_response(response, "Bad account number");
		}
	}
	response_l.add_child("balances", balances);
	response(response_l);
}

void czr::rpc_handler::accounts_create()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			uint64_t count;
			std::string count_text(request.get<std::string>("count"));
			auto count_error(decode_unsigned(count_text, count));
			if (!count_error && count != 0)
			{
				auto existing(node.wallets.items.find(wallet));
				if (existing != node.wallets.items.end())
				{
					const bool generate_work = request.get<bool>("work", false);
					boost::property_tree::ptree response_l;
					boost::property_tree::ptree accounts;
					for (auto i(0); accounts.size() < count; ++i)
					{
						czr::account new_key(existing->second->deterministic_insert(generate_work));
						if (!new_key.is_zero())
						{
							boost::property_tree::ptree entry;
							entry.put("", new_key.to_account());
							accounts.push_back(std::make_pair("", entry));
						}
					}
					response_l.add_child("accounts", accounts);
					response(response_l);
				}
				else
				{
					error_response(response, "Wallet not found");
				}
			}
			else
			{
				error_response(response, "Invalid count limit");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::accounts_frontiers()
{
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree frontiers;
	czr::transaction transaction(node.store.environment, nullptr, false);
	for (auto & accounts : request.get_child("accounts"))
	{
		std::string account_text = accounts.second.data();
		czr::uint256_union account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			auto latest(node.ledger.latest(transaction, account));
			if (!latest.is_zero())
			{
				frontiers.put(account.to_account(), latest.to_string());
			}
		}
		else
		{
			error_response(response, "Bad account number");
		}
	}
	response_l.add_child("frontiers", frontiers);
	response(response_l);
}

void czr::rpc_handler::accounts_pending()
{
	uint64_t count(std::numeric_limits<uint64_t>::max());
	czr::uint128_union threshold(0);
	boost::optional<std::string> count_text(request.get_optional<std::string>("count"));
	if (count_text.is_initialized())
	{
		auto error(decode_unsigned(count_text.get(), count));
		if (error)
		{
			error_response(response, "Invalid count limit");
		}
	}
	boost::optional<std::string> threshold_text(request.get_optional<std::string>("threshold"));
	if (threshold_text.is_initialized())
	{
		auto error_threshold(threshold.decode_dec(threshold_text.get()));
		if (error_threshold)
		{
			error_response(response, "Bad threshold number");
		}
	}
	const bool source = request.get<bool>("source", false);
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree pending;
	czr::transaction transaction(node.store.environment, nullptr, false);
	for (auto & accounts : request.get_child("accounts"))
	{
		std::string account_text = accounts.second.data();
		czr::uint256_union account;
		if (!account.decode_account(account_text))
		{
			boost::property_tree::ptree peers_l;
			czr::account end(account.number() + 1);
			for (auto i(node.store.pending_begin(transaction, czr::pending_key(account, 0))), n(node.store.pending_begin(transaction, czr::pending_key(end, 0))); i != n && peers_l.size() < count; ++i)
			{
				czr::pending_key key(i->first);
				if (threshold.is_zero() && !source)
				{
					boost::property_tree::ptree entry;
					entry.put("", key.hash.to_string());
					peers_l.push_back(std::make_pair("", entry));
				}
				else
				{
					czr::pending_info info(i->second);
					if (info.amount.number() >= threshold.number())
					{
						if (source)
						{
							boost::property_tree::ptree pending_tree;
							pending_tree.put("amount", info.amount.number().convert_to<std::string>());
							pending_tree.put("source", info.source.to_account());
							peers_l.add_child(key.hash.to_string(), pending_tree);
						}
						else
						{
							peers_l.put(key.hash.to_string(), info.amount.number().convert_to<std::string>());
						}
					}
				}
			}
			pending.add_child(account.to_account(), peers_l);
		}
		else
		{
			error_response(response, "Bad account number");
		}
	}
	response_l.add_child("blocks", pending);
	response(response_l);
}

void czr::rpc_handler::block()
{
	std::string hash_text(request.get<std::string>("hash"));
	czr::uint256_union hash;
	auto error(hash.decode_hex(hash_text));
	if (!error)
	{
		czr::transaction transaction(node.store.environment, nullptr, false);
		auto block(node.store.block_get(transaction, hash));
		if (block != nullptr)
		{
			boost::property_tree::ptree response_l;
			std::string contents;
			block->serialize_json(contents);
			response_l.put("contents", contents);
			response(response_l);
		}
		else
		{
			error_response(response, "Block not found");
		}
	}
	else
	{
		error_response(response, "Bad hash number");
	}
}

void czr::rpc_handler::blocks()
{
	std::vector<std::string> hashes;
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree blocks;
	czr::transaction transaction(node.store.environment, nullptr, false);
	for (boost::property_tree::ptree::value_type & hashes : request.get_child("hashes"))
	{
		std::string hash_text = hashes.second.data();
		czr::uint256_union hash;
		auto error(hash.decode_hex(hash_text));
		if (!error)
		{
			auto block(node.store.block_get(transaction, hash));
			if (block != nullptr)
			{
				std::string contents;
				block->serialize_json(contents);
				blocks.put(hash_text, contents);
			}
			else
			{
				error_response(response, "Block not found");
			}
		}
		else
		{
			error_response(response, "Bad hash number");
		}
	}
	response_l.add_child("blocks", blocks);
	response(response_l);
}

void czr::rpc_handler::blocks_info()
{
	const bool pending = request.get<bool>("pending", false);
	const bool source = request.get<bool>("source", false);
	std::vector<std::string> hashes;
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree blocks;
	czr::transaction transaction(node.store.environment, nullptr, false);
	for (boost::property_tree::ptree::value_type & hashes : request.get_child("hashes"))
	{
		std::string hash_text = hashes.second.data();
		czr::uint256_union hash;
		auto error(hash.decode_hex(hash_text));
		if (!error)
		{
			auto block(node.store.block_get(transaction, hash));
			if (block != nullptr)
			{
				boost::property_tree::ptree entry;
				auto amount(node.ledger.block_amount(transaction, *block));
				entry.put("amount", amount.convert_to<std::string>());
				std::string contents;
				block->serialize_json(contents);
				entry.put("contents", contents);
				if (pending)
				{
					bool exists(false);
					auto destination(node.ledger.block_destination(transaction, *block));
					if (!destination.is_zero())
					{
						exists = node.store.pending_exists(transaction, czr::pending_key(destination, hash));
					}
					entry.put("pending", exists ? "1" : "0");
				}
				if (source)
				{
					czr::block_hash source_hash(node.ledger.block_source(transaction, *block));
					std::unique_ptr<czr::block> block_a(node.store.block_get(transaction, source_hash));
					if (block_a != nullptr)
					{
						auto source_account(node.ledger.account(transaction, source_hash));
						entry.put("source_account", source_account.to_account());
					}
					else
					{
						entry.put("source_account", "0");
					}
				}
				blocks.push_back(std::make_pair(hash_text, entry));
			}
			else
			{
				error_response(response, "Block not found");
			}
		}
		else
		{
			error_response(response, "Bad hash number");
		}
	}
	response_l.add_child("blocks", blocks);
	response(response_l);
}

void czr::rpc_handler::block_account()
{
	std::string hash_text(request.get<std::string>("hash"));
	czr::block_hash hash;
	if (!hash.decode_hex(hash_text))
	{
		czr::transaction transaction(node.store.environment, nullptr, false);
		if (node.store.block_exists(transaction, hash))
		{
			boost::property_tree::ptree response_l;
			auto account(node.ledger.account(transaction, hash));
			response_l.put("account", account.to_account());
			response(response_l);
		}
		else
		{
			error_response(response, "Block not found");
		}
	}
	else
	{
		error_response(response, "Invalid block hash");
	}
}

void czr::rpc_handler::block_count()
{
	czr::transaction transaction(node.store.environment, nullptr, false);
	boost::property_tree::ptree response_l;
	response_l.put("count", std::to_string(node.store.block_count(transaction)));
	response_l.put("unchecked", std::to_string(node.store.unchecked_count(transaction)));
	response(response_l);
}

void czr::rpc_handler::deterministic_key()
{
	std::string seed_text(request.get<std::string>("seed"));
	std::string index_text(request.get<std::string>("index"));
	czr::raw_key seed;
	auto error(seed.data.decode_hex(seed_text));
	if (!error)
	{
		uint64_t index_a;
		if (!decode_unsigned(index_text, index_a))
		{
			czr::uint256_union index(index_a);
			czr::uint256_union prv;
			blake2b_state hash;
			blake2b_init(&hash, prv.bytes.size());
			blake2b_update(&hash, seed.data.bytes.data(), seed.data.bytes.size());
			blake2b_update(&hash, reinterpret_cast<uint8_t *> (&index.dwords[7]), sizeof(uint32_t));
			blake2b_final(&hash, prv.bytes.data(), prv.bytes.size());
			boost::property_tree::ptree response_l;
			czr::uint256_union pub;
			ed25519_publickey(prv.bytes.data(), pub.bytes.data());
			response_l.put("private", prv.to_string());
			response_l.put("public", pub.to_string());
			response_l.put("account", pub.to_account());
			response(response_l);
		}
		else
		{
			error_response(response, "Invalid index");
		}
	}
	else
	{
		error_response(response, "Bad seed");
	}
}

void czr::rpc_handler::key_create()
{
	boost::property_tree::ptree response_l;
	czr::keypair pair;
	response_l.put("private", pair.prv.data.to_string());
	response_l.put("public", pair.pub.to_string());
	response_l.put("account", pair.pub.to_account());
	response(response_l);
}

void czr::rpc_handler::czr_from_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() / czr::czr_ratio);
		boost::property_tree::ptree response_l;
		response_l.put("amount", result.convert_to<std::string>());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::czr_to_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() * czr::czr_ratio);
		if (result > amount.number())
		{
			boost::property_tree::ptree response_l;
			response_l.put("amount", result.convert_to<std::string>());
			response(response_l);
		}
		else
		{
			error_response(response, "Amount too big");
		}
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::mczr_from_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() / czr::Mczr_ratio);
		boost::property_tree::ptree response_l;
		response_l.put("amount", result.convert_to<std::string>());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::mczr_to_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() * czr::Mczr_ratio);
		if (result > amount.number())
		{
			boost::property_tree::ptree response_l;
			response_l.put("amount", result.convert_to<std::string>());
			response(response_l);
		}
		else
		{
			error_response(response, "Amount too big");
		}
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::kczr_from_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() / czr::kczr_ratio);
		boost::property_tree::ptree response_l;
		response_l.put("amount", result.convert_to<std::string>());
		response(response_l);
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::kczr_to_raw()
{
	std::string amount_text(request.get<std::string>("amount"));
	czr::uint128_union amount;
	if (!amount.decode_dec(amount_text))
	{
		auto result(amount.number() * czr::kczr_ratio);
		if (result > amount.number())
		{
			boost::property_tree::ptree response_l;
			response_l.put("amount", result.convert_to<std::string>());
			response(response_l);
		}
		else
		{
			error_response(response, "Amount too big");
		}
	}
	else
	{
		error_response(response, "Bad amount number");
	}
}

void czr::rpc_handler::password_change()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				czr::transaction transaction(node.store.environment, nullptr, true);
				boost::property_tree::ptree response_l;
				std::string password_text(request.get<std::string>("password"));
				auto error(existing->second->store.rekey(transaction, password_text));
				response_l.put("changed", error ? "0" : "1");
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::password_enter()
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			boost::property_tree::ptree response_l;
			std::string password_text(request.get<std::string>("password"));
			auto error(existing->second->enter_password(password_text));
			response_l.put("valid", error ? "0" : "1");
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad wallet number");
	}
}

void czr::rpc_handler::password_valid(bool wallet_locked = false)
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			czr::transaction transaction(node.store.environment, nullptr, false);
			boost::property_tree::ptree response_l;
			auto valid(existing->second->store.valid_password(transaction));
			if (!wallet_locked)
			{
				response_l.put("valid", valid ? "1" : "0");
			}
			else
			{
				response_l.put("locked", valid ? "0" : "1");
			}
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad wallet number");
	}
}

void czr::rpc_handler::pending()
{
	std::string account_text(request.get<std::string>("account"));
	czr::account account;
	if (!account.decode_account(account_text))
	{
		uint64_t count(std::numeric_limits<uint64_t>::max());
		czr::uint128_union threshold(0);
		boost::optional<std::string> count_text(request.get_optional<std::string>("count"));
		if (count_text.is_initialized())
		{
			auto error(decode_unsigned(count_text.get(), count));
			if (error)
			{
				error_response(response, "Invalid count limit");
			}
		}
		boost::optional<std::string> threshold_text(request.get_optional<std::string>("threshold"));
		if (threshold_text.is_initialized())
		{
			auto error_threshold(threshold.decode_dec(threshold_text.get()));
			if (error_threshold)
			{
				error_response(response, "Bad threshold number");
			}
		}
		const bool source = request.get<bool>("source", false);
		boost::property_tree::ptree response_l;
		boost::property_tree::ptree peers_l;
		{
			czr::transaction transaction(node.store.environment, nullptr, false);
			czr::account end(account.number() + 1);
			for (auto i(node.store.pending_begin(transaction, czr::pending_key(account, 0))), n(node.store.pending_begin(transaction, czr::pending_key(end, 0))); i != n && peers_l.size() < count; ++i)
			{
				czr::pending_key key(i->first);
				if (threshold.is_zero() && !source)
				{
					boost::property_tree::ptree entry;
					entry.put("", key.hash.to_string());
					peers_l.push_back(std::make_pair("", entry));
				}
				else
				{
					czr::pending_info info(i->second);
					if (info.amount.number() >= threshold.number())
					{
						if (source)
						{
							boost::property_tree::ptree pending_tree;
							pending_tree.put("amount", info.amount.number().convert_to<std::string>());
							pending_tree.put("source", info.source.to_account());
							peers_l.add_child(key.hash.to_string(), pending_tree);
						}
						else
						{
							peers_l.put(key.hash.to_string(), info.amount.number().convert_to<std::string>());
						}
					}
				}
			}
		}
		response_l.add_child("blocks", peers_l);
		response(response_l);
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::search_pending()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				auto error(existing->second->search_pending());
				boost::property_tree::ptree response_l;
				response_l.put("started", !error);
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::search_pending_all()
{
	if (rpc.config.enable_control)
	{
		node.wallets.search_pending_all();
		boost::property_tree::ptree response_l;
		response_l.put("success", "");
		response(response_l);
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::receive_minimum()
{
	if (rpc.config.enable_control)
	{
		boost::property_tree::ptree response_l;
		response_l.put("amount", node.config.receive_minimum.to_string_dec());
		response(response_l);
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::receive_minimum_set()
{
	if (rpc.config.enable_control)
	{
		std::string amount_text(request.get<std::string>("amount"));
		czr::uint128_union amount;
		if (!amount.decode_dec(amount_text))
		{
			node.config.receive_minimum = amount;
			boost::property_tree::ptree response_l;
			response_l.put("success", "");
			response(response_l);
		}
		else
		{
			error_response(response, "Bad amount number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::send()
{
	//todo:send block
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				std::string source_text(request.get<std::string>("source"));
				czr::account source;
				auto error(source.decode_account(source_text));
				if (!error)
				{
					std::string destination_text(request.get<std::string>("destination"));
					czr::account destination;
					auto error(destination.decode_account(destination_text));
					if (!error)
					{
						std::string amount_text(request.get<std::string>("amount"));
						czr::amount amount;
						auto error(amount.decode_dec(amount_text));
						if (!error)
						{
							uint64_t work(0);
							boost::optional<std::string> work_text(request.get_optional<std::string>("work"));
							if (work_text.is_initialized())
							{
								auto work_error(czr::from_string_hex(work_text.get(), work));
								if (work_error)
								{
									error_response(response, "Bad work");
								}
							}
							czr::uint128_t balance(0);
							{
								czr::transaction transaction(node.store.environment, nullptr, work != 0); // false if no "work" in request, true if work > 0
								czr::account_info info;
								if (!node.store.account_get(transaction, source, info))
								{
									balance = (info.balance).number();
								}
								else
								{
									error_response(response, "Account not found");
								}
								if (work)
								{
									if (!czr::work_validate(info.head, work))
									{
										existing->second->store.work_put(transaction, source, work);
									}
									else
									{
										error_response(response, "Invalid work");
									}
								}
							}
							boost::optional<std::string> send_id(request.get_optional<std::string>("id"));
							if (balance >= amount.number())
							{
								auto rpc_l(shared_from_this());
								auto response_a(response);
								existing->second->send_async(source, destination, amount.number(), [response_a](std::shared_ptr<czr::block> block_a) {
									if (block_a != nullptr)
									{
										czr::uint256_union hash(block_a->hash());
										boost::property_tree::ptree response_l;
										response_l.put("block", hash.to_string());
										response_a(response_l);
									}
									else
									{
										error_response(response_a, "Error generating block");
									}
								},
									work == 0, send_id);
							}
							else
							{
								error_response(response, "Insufficient balance");
							}
						}
						else
						{
							error_response(response, "Bad amount format");
						}
					}
					else
					{
						error_response(response, "Bad destination account");
					}
				}
				else
				{
					error_response(response, "Bad source account");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::stop()
{
	if (rpc.config.enable_control)
	{
		boost::property_tree::ptree response_l;
		response_l.put("success", "");
		response(response_l);
		rpc.stop();
		node.stop();
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::version()
{
	boost::property_tree::ptree response_l;
	response_l.put("rpc_version", "1");
	response_l.put("store_version", std::to_string(node.store_version()));
	response_l.put("node_vendor", boost::str(boost::format("Canonchain %1%.%2%") % CANONCHAIN_VERSION_MAJOR % CANONCHAIN_VERSION_MINOR));
	response(response_l);
}

void czr::rpc_handler::validate_account_number()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	boost::property_tree::ptree response_l;
	response_l.put("valid", error ? "0" : "1");
	response(response_l);
}

void czr::rpc_handler::wallet_add()
{
	if (rpc.config.enable_control)
	{
		std::string key_text(request.get<std::string>("key"));
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::raw_key key;
		auto error(key.data.decode_hex(key_text));
		if (!error)
		{
			czr::uint256_union wallet;
			auto error(wallet.decode_hex(wallet_text));
			if (!error)
			{
				auto existing(node.wallets.items.find(wallet));
				if (existing != node.wallets.items.end())
				{
					const bool generate_work = request.get<bool>("work", true);
					auto pub(existing->second->insert_adhoc(key, generate_work));
					if (!pub.is_zero())
					{
						boost::property_tree::ptree response_l;
						response_l.put("account", pub.to_account());
						response(response_l);
					}
					else
					{
						error_response(response, "Wallet locked");
					}
				}
				else
				{
					error_response(response, "Wallet not found");
				}
			}
			else
			{
				error_response(response, "Bad wallet number");
			}
		}
		else
		{
			error_response(response, "Bad private key");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_add_watch()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				czr::transaction transaction(node.store.environment, nullptr, true);
				if (existing->second->store.valid_password(transaction))
				{
					for (auto & accounts : request.get_child("accounts"))
					{
						std::string account_text = accounts.second.data();
						czr::uint256_union account;
						auto error(account.decode_account(account_text));
						if (!error)
						{
							existing->second->insert_watch(transaction, account);
						}
						else
						{
							error_response(response, "Bad account number");
						}
					}
					boost::property_tree::ptree response_l;
					response_l.put("success", "");
					response(response_l);
				}
				else
				{
					error_response(response, "Wallet locked");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_balances()
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		czr::uint128_union threshold(0);
		boost::optional<std::string> threshold_text(request.get_optional<std::string>("threshold"));
		if (threshold_text.is_initialized())
		{
			auto error_threshold(threshold.decode_dec(threshold_text.get()));
			if (error_threshold)
			{
				error_response(response, "Bad threshold number");
			}
		}
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			boost::property_tree::ptree response_l;
			boost::property_tree::ptree balances;
			czr::transaction transaction(node.store.environment, nullptr, false);
			for (auto i(existing->second->store.begin(transaction)), n(existing->second->store.end()); i != n; ++i)
			{
				czr::account account(i->first.uint256());
				czr::uint128_t balance = node.ledger.account_balance(transaction, account);
				if (threshold.is_zero())
				{
					boost::property_tree::ptree entry;
					czr::uint128_t pending = node.ledger.account_pending(transaction, account);
					entry.put("balance", balance.convert_to<std::string>());
					entry.put("pending", pending.convert_to<std::string>());
					balances.push_back(std::make_pair(account.to_account(), entry));
				}
				else
				{
					if (balance >= threshold.number())
					{
						boost::property_tree::ptree entry;
						czr::uint128_t pending = node.ledger.account_pending(transaction, account);
						entry.put("balance", balance.convert_to<std::string>());
						entry.put("pending", pending.convert_to<std::string>());
						balances.push_back(std::make_pair(account.to_account(), entry));
					}
				}
			}
			response_l.add_child("balances", balances);
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad wallet number");
	}
}

void czr::rpc_handler::wallet_change_seed()
{
	if (rpc.config.enable_control)
	{
		std::string seed_text(request.get<std::string>("seed"));
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::raw_key seed;
		auto error(seed.data.decode_hex(seed_text));
		if (!error)
		{
			czr::uint256_union wallet;
			auto error(wallet.decode_hex(wallet_text));
			if (!error)
			{
				auto existing(node.wallets.items.find(wallet));
				if (existing != node.wallets.items.end())
				{
					czr::transaction transaction(node.store.environment, nullptr, true);
					if (existing->second->store.valid_password(transaction))
					{
						existing->second->store.seed_set(transaction, seed);
						boost::property_tree::ptree response_l;
						response_l.put("success", "");
						response(response_l);
					}
					else
					{
						error_response(response, "Wallet locked");
					}
				}
				else
				{
					error_response(response, "Wallet not found");
				}
			}
			else
			{
				error_response(response, "Bad wallet number");
			}
		}
		else
		{
			error_response(response, "Bad seed");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_contains()
{
	std::string account_text(request.get<std::string>("account"));
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				czr::transaction transaction(node.store.environment, nullptr, false);
				auto exists(existing->second->store.find(transaction, account) != existing->second->store.end());
				boost::property_tree::ptree response_l;
				response_l.put("exists", exists ? "1" : "0");
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::wallet_create()
{
	if (rpc.config.enable_control)
	{
		czr::keypair wallet_id;
		node.wallets.create(wallet_id.pub);
		czr::transaction transaction(node.store.environment, nullptr, false);
		auto existing(node.wallets.items.find(wallet_id.pub));
		if (existing != node.wallets.items.end())
		{
			boost::property_tree::ptree response_l;
			response_l.put("wallet", wallet_id.pub.to_string());
			response(response_l);
		}
		else
		{
			error_response(response, "Failed to create wallet. Increase lmdb_max_dbs in node config.");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_destroy()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				node.wallets.destroy(wallet);
				boost::property_tree::ptree response_l;
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_export()
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			czr::transaction transaction(node.store.environment, nullptr, false);
			std::string json;
			existing->second->store.serialize_json(transaction, json);
			boost::property_tree::ptree response_l;
			response_l.put("json", json);
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad account number");
	}
}

void czr::rpc_handler::wallet_key_valid()
{
	std::string wallet_text(request.get<std::string>("wallet"));
	czr::uint256_union wallet;
	auto error(wallet.decode_hex(wallet_text));
	if (!error)
	{
		auto existing(node.wallets.items.find(wallet));
		if (existing != node.wallets.items.end())
		{
			czr::transaction transaction(node.store.environment, nullptr, false);
			auto valid(existing->second->store.valid_password(transaction));
			boost::property_tree::ptree response_l;
			response_l.put("valid", valid ? "1" : "0");
			response(response_l);
		}
		else
		{
			error_response(response, "Wallet not found");
		}
	}
	else
	{
		error_response(response, "Bad wallet number");
	}
}

void czr::rpc_handler::wallet_lock()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				boost::property_tree::ptree response_l;
				czr::raw_key empty;
				empty.data.clear();
				existing->second->store.password.value_set(empty);
				response_l.put("locked", "1");
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::wallet_work_get()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				boost::property_tree::ptree response_l;
				boost::property_tree::ptree works;
				czr::transaction transaction(node.store.environment, nullptr, false);
				for (auto i(existing->second->store.begin(transaction)), n(existing->second->store.end()); i != n; ++i)
				{
					czr::account account(i->first.uint256());
					uint64_t work(0);
					auto error_work(existing->second->store.work_get(transaction, account, work));
					works.put(account.to_account(), czr::to_string_hex(work));
				}
				response_l.add_child("works", works);
				response(response_l);
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_generate()
{
	if (rpc.config.enable_control)
	{
		std::string hash_text(request.get<std::string>("hash"));
		czr::block_hash hash;
		auto error(hash.decode_hex(hash_text));
		if (!error)
		{
			auto rpc_l(shared_from_this());
			node.work.generate(hash, [rpc_l](boost::optional<uint64_t> const & work_a) {
				if (work_a)
				{
					boost::property_tree::ptree response_l;
					response_l.put("work", czr::to_string_hex(work_a.value()));
					rpc_l->response(response_l);
				}
				else
				{
					error_response(rpc_l->response, "Cancelled");
				}
			});
		}
		else
		{
			error_response(response, "Bad block hash");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_cancel()
{
	if (rpc.config.enable_control)
	{
		std::string hash_text(request.get<std::string>("hash"));
		czr::block_hash hash;
		auto error(hash.decode_hex(hash_text));
		if (!error)
		{
			node.work.cancel(hash);
			boost::property_tree::ptree response_l;
			response(response_l);
		}
		else
		{
			error_response(response, "Bad block hash");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_get()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				std::string account_text(request.get<std::string>("account"));
				czr::account account;
				auto error(account.decode_account(account_text));
				if (!error)
				{
					czr::transaction transaction(node.store.environment, nullptr, false);
					auto account_check(existing->second->store.find(transaction, account));
					if (account_check != existing->second->store.end())
					{
						uint64_t work(0);
						auto error_work(existing->second->store.work_get(transaction, account, work));
						boost::property_tree::ptree response_l;
						response_l.put("work", czr::to_string_hex(work));
						response(response_l);
					}
					else
					{
						error_response(response, "Account not found in wallet");
					}
				}
				else
				{
					error_response(response, "Bad account number");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_set()
{
	if (rpc.config.enable_control)
	{
		std::string wallet_text(request.get<std::string>("wallet"));
		czr::uint256_union wallet;
		auto error(wallet.decode_hex(wallet_text));
		if (!error)
		{
			auto existing(node.wallets.items.find(wallet));
			if (existing != node.wallets.items.end())
			{
				std::string account_text(request.get<std::string>("account"));
				czr::account account;
				auto error(account.decode_account(account_text));
				if (!error)
				{
					czr::transaction transaction(node.store.environment, nullptr, true);
					auto account_check(existing->second->store.find(transaction, account));
					if (account_check != existing->second->store.end())
					{
						std::string work_text(request.get<std::string>("work"));
						uint64_t work;
						auto work_error(czr::from_string_hex(work_text, work));
						if (!work_error)
						{
							existing->second->store.work_put(transaction, account, work);
							boost::property_tree::ptree response_l;
							response_l.put("success", "");
							response(response_l);
						}
						else
						{
							error_response(response, "Bad work");
						}
					}
					else
					{
						error_response(response, "Account not found in wallet");
					}
				}
				else
				{
					error_response(response, "Bad account number");
				}
			}
			else
			{
				error_response(response, "Wallet not found");
			}
		}
		else
		{
			error_response(response, "Bad wallet number");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_validate()
{
	std::string hash_text(request.get<std::string>("hash"));
	czr::block_hash hash;
	auto error(hash.decode_hex(hash_text));
	if (!error)
	{
		std::string work_text(request.get<std::string>("work"));
		uint64_t work;
		auto work_error(czr::from_string_hex(work_text, work));
		if (!work_error)
		{
			auto validate(czr::work_validate(hash, work));
			boost::property_tree::ptree response_l;
			response_l.put("valid", validate ? "0" : "1");
			response(response_l);
		}
		else
		{
			error_response(response, "Bad work");
		}
	}
	else
	{
		error_response(response, "Bad block hash");
	}
}

void czr::rpc_handler::work_peer_add()
{
	if (rpc.config.enable_control)
	{
		std::string address_text = request.get<std::string>("address");
		std::string port_text = request.get<std::string>("port");
		boost::system::error_code ec;
		auto address(boost::asio::ip::address_v6::from_string(address_text, ec));
		if (!ec)
		{
			uint16_t port;
			if (!czr::parse_port(port_text, port))
			{
				node.config.work_peers.push_back(std::make_pair(address, port));
				boost::property_tree::ptree response_l;
				response_l.put("success", "");
				response(response_l);
			}
			else
			{
				error_response(response, "Invalid port");
			}
		}
		else
		{
			error_response(response, "Invalid address");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_peers()
{
	if (rpc.config.enable_control)
	{
		boost::property_tree::ptree work_peers_l;
		for (auto i(node.config.work_peers.begin()), n(node.config.work_peers.end()); i != n; ++i)
		{
			boost::property_tree::ptree entry;
			entry.put("", boost::str(boost::format("%1%:%2%") % i->first % i->second));
			work_peers_l.push_back(std::make_pair("", entry));
		}
		boost::property_tree::ptree response_l;
		response_l.add_child("work_peers", work_peers_l);
		response(response_l);
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::work_peers_clear()
{
	if (rpc.config.enable_control)
	{
		node.config.work_peers.clear();
		boost::property_tree::ptree response_l;
		response_l.put("success", "");
		response(response_l);
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

czr::rpc_connection::rpc_connection(czr::node & node_a, czr::rpc & rpc_a) :
	node(node_a.shared()),
	rpc(rpc_a),
	socket(node_a.service)
{
	responded.clear();
}

void czr::rpc_connection::parse_connection()
{
	read();
}

void czr::rpc_connection::write_result(std::string body, unsigned version)
{
	if (!responded.test_and_set())
	{
		res.set("Content-Type", "application/json");
		res.set("Access-Control-Allow-Origin", "*");
		res.set("Access-Control-Allow-Headers", "Accept, Accept-Language, Content-Language, Content-Type");
		res.set("Connection", "close");
		res.result(boost::beast::http::status::ok);
		res.body() = body;
		res.version(version);
		res.prepare_payload();
	}
	else
	{
		assert(false && "RPC already responded and should only respond once");
		// Guards `res' from being clobbered while async_write is being serviced
	}
}

void czr::rpc_connection::read()
{
	auto this_l(shared_from_this());
	boost::beast::http::async_read(socket, buffer, request, [this_l](boost::system::error_code const & ec, size_t bytes_transferred) {
		if (!ec)
		{
			this_l->node->background([this_l]() {
				auto start(std::chrono::steady_clock::now());
				auto version(this_l->request.version());
				auto response_handler([this_l, version, start](boost::property_tree::ptree const & tree_a) {

					std::stringstream ostream;
					boost::property_tree::write_json(ostream, tree_a);
					ostream.flush();
					auto body(ostream.str());
					this_l->write_result(body, version);
					boost::beast::http::async_write(this_l->socket, this_l->res, [this_l](boost::system::error_code const & ec, size_t bytes_transferred) {
					});

					if (this_l->node->config.logging.log_rpc())
					{
						BOOST_LOG(this_l->node->log) << boost::str(boost::format("RPC request %2% completed in: %1% microseconds") % std::chrono::duration_cast<std::chrono::microseconds> (std::chrono::steady_clock::now() - start).count() % boost::io::group(std::hex, std::showbase, reinterpret_cast<uintptr_t> (this_l.get())));
					}
				});
				if (this_l->request.method() == boost::beast::http::verb::post)
				{
					auto handler(std::make_shared<czr::rpc_handler>(*this_l->node, this_l->rpc, this_l->request.body(), response_handler));
					handler->process_request();
				}
				else
				{
					error_response(response_handler, "Can only POST requests");
				}
			});
		}
		else
		{
			BOOST_LOG(this_l->node->log) << "RPC read error: " << ec.message();
		}
	});
}

namespace
{
	void reprocess_body(std::string & body, boost::property_tree::ptree & tree_a)
	{
		std::stringstream stream;
		boost::property_tree::write_json(stream, tree_a);
		body = stream.str();
	}
}

void czr::rpc_handler::process_request()
{
	try
	{
		std::stringstream istream(body);
		boost::property_tree::read_json(istream, request);
		std::string action(request.get<std::string>("action"));
		if (action == "password_enter")
		{
			password_enter();
			request.erase("password");
			reprocess_body(body, request);
		}
		else if (action == "password_change")
		{
			password_change();
			request.erase("password");
			reprocess_body(body, request);
		}
		else if (action == "wallet_unlock")
		{
			password_enter();
			request.erase("password");
			reprocess_body(body, request);
		}
		if (node.config.logging.log_rpc())
		{
			BOOST_LOG(node.log) << body;
		}

		if (action == "account_balance")
		{
			account_balance();
		}
		else if (action == "account_block_count")
		{
			account_block_count();
		}
		else if (action == "account_create")
		{
			account_create();
		}
		else if (action == "account_get")
		{
			account_get();
		}
		else if (action == "account_info")
		{
			account_info();
		}
		else if (action == "account_key")
		{
			account_key();
		}
		else if (action == "account_list")
		{
			account_list();
		}
		else if (action == "account_move")
		{
			account_move();
		}
		else if (action == "account_remove")
		{
			account_remove();
		}
		else if (action == "accounts_balances")
		{
			accounts_balances();
		}
		else if (action == "accounts_create")
		{
			accounts_create();
		}
		else if (action == "accounts_frontiers")
		{
			accounts_frontiers();
		}
		else if (action == "accounts_pending")
		{
			accounts_pending();
		}

		else if (action == "block")
		{
			block();
		}
		else if (action == "blocks")
		{
			blocks();
		}
		else if (action == "blocks_info")
		{
			blocks_info();
		}
		else if (action == "block_account")
		{
			block_account();
		}
		else if (action == "block_count")
		{
			block_count();
		}
		else if (action == "deterministic_key")
		{
			deterministic_key();
		}
		else if (action == "key_create")
		{
			key_create();
		}
		else if (action == "kczr_from_raw")
		{
			kczr_from_raw();
		}
		else if (action == "kczr_to_raw")
		{
			kczr_to_raw();
		}
		else if (action == "mczr_from_raw")
		{
			mczr_from_raw();
		}
		else if (action == "mczr_to_raw")
		{
			mczr_to_raw();
		}
		else if (action == "password_valid")
		{
			password_valid();
		}
		else if (action == "pending")
		{
			pending();
		}
		else if (action == "czr_from_raw")
		{
			czr_from_raw();
		}
		else if (action == "czr_to_raw")
		{
			czr_to_raw();
		}
		else if (action == "receive_minimum")
		{
			receive_minimum();
		}
		else if (action == "receive_minimum_set")
		{
			receive_minimum_set();
		}
		else if (action == "search_pending")
		{
			search_pending();
		}
		else if (action == "search_pending_all")
		{
			search_pending_all();
		}
		else if (action == "send")
		{
			send();
		}
		else if (action == "stop")
		{
			stop();
		}
		else if (action == "validate_account_number")
		{
			validate_account_number();
		}
		else if (action == "version")
		{
			version();
		}
		else if (action == "wallet_add")
		{
			wallet_add();
		}
		else if (action == "wallet_add_watch")
		{
			wallet_add_watch();
		}
		else if (action == "wallet_balances")
		{
			wallet_balances();
		}
		else if (action == "wallet_change_seed")
		{
			wallet_change_seed();
		}
		else if (action == "wallet_contains")
		{
			wallet_contains();
		}
		else if (action == "wallet_create")
		{
			wallet_create();
		}
		else if (action == "wallet_destroy")
		{
			wallet_destroy();
		}
		else if (action == "wallet_export")
		{
			wallet_export();
		}
		else if (action == "wallet_key_valid")
		{
			wallet_key_valid();
		}
		else if (action == "wallet_lock")
		{
			wallet_lock();
		}
		else if (action == "wallet_locked")
		{
			password_valid(true);
		}
		else if (action == "wallet_work_get")
		{
			wallet_work_get();
		}
		else if (action == "work_generate")
		{
			work_generate();
		}
		else if (action == "work_cancel")
		{
			work_cancel();
		}
		else if (action == "work_get")
		{
			work_get();
		}
		else if (action == "work_set")
		{
			work_set();
		}
		else if (action == "work_validate")
		{
			work_validate();
		}
		else if (action == "work_peer_add")
		{
			work_peer_add();
		}
		else if (action == "work_peers")
		{
			work_peers();
		}
		else if (action == "work_peers_clear")
		{
			work_peers_clear();
		}
		else
		{
			error_response(response, "Unknown command");
		}
	}
	catch (std::runtime_error const & err)
	{
		error_response(response, "Unable to parse JSON");
	}
	catch (...)
	{
		error_response(response, "Internal server error in RPC");
	}
}

std::unique_ptr<czr::rpc> czr::get_rpc(boost::asio::io_service & service_a, czr::node & node_a, czr::rpc_config const & config_a)
{
	std::unique_ptr<rpc> impl;

	if (config_a.secure.enable)
	{
#ifdef CANONCHAIN_SECURE_RPC
		impl.reset(new rpc_secure(service_a, node_a, config_a));
#else
		std::cerr << "RPC configured for TLS, but the node is not compiled with TLS support" << std::endl;
#endif
	}
	else
	{
		impl.reset(new rpc(service_a, node_a, config_a));
	}

	return impl;
}
