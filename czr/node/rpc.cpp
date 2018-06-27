#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/optional.hpp>
#include <czr/node/rpc.hpp>

#include <czr/node/node.hpp>
#include <czr/node/composer.hpp>

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
	address(boost::asio::ip::address_v4::loopback()),
	port(czr::rpc::rpc_port),
	enable_control(false)
{
}

czr::rpc_config::rpc_config(bool enable_control_a) :
	address(boost::asio::ip::address_v4::loopback()),
	port(czr::rpc::rpc_port),
	enable_control(enable_control_a)
{
}

void czr::rpc_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("address", address.to_string());
	tree_a.put("port", std::to_string(port));
	tree_a.put("enable_control", enable_control);
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
			try
			{
				port = std::stoul(port_l);
				result = port > std::numeric_limits<uint16_t>::max();
			}
			catch (std::logic_error const &)
			{
				result = true;
			}
			boost::system::error_code ec;
			address = boost::asio::ip::address::from_string(address_l, ec);
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
	auto endpoint(bi::tcp::endpoint(config.address, config.port));
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

void czr::rpc_handler::account_list()
{
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree accounts;

	std::list<czr::account> account_list(node.key_manager.list());
	for (auto account : account_list)
	{
		boost::property_tree::ptree entry;
		entry.put("", account.to_account());
		accounts.push_back(std::make_pair("", entry));
	}
	response_l.add_child("accounts", accounts);
	response(response_l);
}

void czr::rpc_handler::account_validate()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	boost::property_tree::ptree response_l;
	response_l.put("valid", error ? "0" : "1");
	response(response_l);
}

void czr::rpc_handler::account_create()
{
	if (rpc.config.enable_control)
	{
		std::string password(request.get<std::string>("password"));
		if (!password.empty())
		{
			czr::transaction transaction(node.store.environment, nullptr, true);
			czr::account new_account(node.key_manager.create(transaction, password));
			boost::property_tree::ptree response_l;
			response_l.put("account", new_account.to_account());
			response(response_l);
		}
		else
		{
			error_response(response, "Password can not be empty");
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
		std::string account_text(request.get<std::string>("account"));
		czr::account account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			bool exists(node.key_manager.exists(account));
			if (exists)
			{
				std::string password_text(request.get<std::string>("password"));
				czr::transaction transaction(node.store.environment, nullptr, true);
				bool error(node.key_manager.remove(transaction, account, password_text));
				if (!error)
				{
					boost::property_tree::ptree response_l;
					response_l.put("success", "1");
					response(response_l);
				}
				else
				{
					error_response(response, "Wrong password");
				}
			}
			else
			{
				error_response(response, "Account not found");
			}
		}
		else
		{
			error_response(response, "Invalid account");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_password_change()
{
	if (rpc.config.enable_control)
	{
		std::string account_text(request.get<std::string>("account"));
		czr::account account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			auto exists(node.key_manager.exists(account));
			if (exists)
			{
				czr::transaction transaction(node.store.environment, nullptr, true);
				std::string old_password_text(request.get<std::string>("old_password"));
				std::string new_password_text(request.get<std::string>("new_password"));
				auto error(node.key_manager.change_password(transaction, account, old_password_text, new_password_text));

				boost::property_tree::ptree response_l;
				response_l.put("success", error ? "0" : "1");
				response(response_l);
			}
			else
			{
				error_response(response, "Account not found");
			}
		}
		else
		{
			error_response(response, "Invalid account");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_unlock()
{
	if (rpc.config.enable_control)
	{
		std::string account_text(request.get<std::string>("account"));
		czr::account account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			auto exists(node.key_manager.exists(account));
			if (exists)
			{
				std::string password_text(request.get<std::string>("password"));
				auto error(node.key_manager.unlock(account, password_text));
				if (!error)
				{
					boost::property_tree::ptree response_l;
					response_l.put("success", "1");
					response(response_l);
				}
				else
				{
					error_response(response, "Wrong password");
				}
			}
			else
			{
				error_response(response, "Account not found");
			}
		}
		else
		{
			error_response(response, "Invalid account");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_lock()
{
	if (rpc.config.enable_control)
	{
		std::string account_text(request.get<std::string>("account"));
		czr::account account;
		auto error(account.decode_account(account_text));
		if (!error)
		{
			auto exists(node.key_manager.exists(account));
			if (exists)
			{
				node.key_manager.lock(account);
				boost::property_tree::ptree response_l;
				response_l.put("success", "1");
				response(response_l);
			}
			else
			{
				error_response(response, "Account not found");
			}
		}
		else
		{
			error_response(response, "Invalid account");
		}
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}

void czr::rpc_handler::account_export()
{
	std::string account_text(request.get<std::string>("account"));
	czr::account account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		czr::key_content kc;
		auto exists(node.key_manager.find(account, kc));
		if (exists)
		{
			boost::property_tree::ptree response_l;
			std::string & json(kc.to_json());
			response_l.put("json",json);
			response(response_l);
		}
		else
		{
			error_response(response, "Account not found");
		}
	}
	else
	{
		error_response(response, "Invalid account");
	}
}

void czr::rpc_handler::account_import()
{
	if (rpc.config.enable_control)
	{
		std::string json_text(request.get<std::string>("json"));

		czr::key_content kc;
		czr::transaction transaction(node.store.environment, nullptr, true);
		auto error(node.key_manager.import(transaction, json_text, kc));

		boost::property_tree::ptree response_l;
		response_l.put("success", error ? "0" : "1");
		response_l.put("account", error ? "" : kc.account.to_account());
		response(response_l);
	}
	else
	{
		error_response(response, "RPC control is disabled");
	}
}


void czr::rpc_handler::account_balance()
{
	std::string account_text(request.get<std::string>("account"));
	czr::uint256_union account;
	auto error(account.decode_account(account_text));
	if (!error)
	{
		czr::transaction transaction(node.store.environment, nullptr, false);;
		auto balance(node.ledger.account_balance(transaction, account));
		boost::property_tree::ptree response_l;
		response_l.put("balance", balance.convert_to<std::string>());
		response(response_l);
	}
	else
	{
		error_response(response, "Invalid account");
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
			czr::transaction transaction(node.store.environment, nullptr, false);;
			auto balance(node.ledger.account_balance(transaction, account));
			entry.put("balance", balance.convert_to<std::string>());
			balances.push_back(std::make_pair(account.to_account(), entry));
		}
		else
		{
			error_response(response, "Invalid account");
		}
	}
	response_l.add_child("balances", balances);
	response(response_l);
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
		error_response(response, "Invalid account");
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

			error_response(response, "Invalid account");
		}
	}
	response_l.add_child("frontiers", frontiers);
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

		error_response(response, "Invalid hash");
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

			error_response(response, "Invalid hash");
		}
	}
	response_l.add_child("blocks", blocks);
	response(response_l);
}

void czr::rpc_handler::block_count()
{
	czr::transaction transaction(node.store.environment, nullptr, false);
	boost::property_tree::ptree response_l;
	response_l.put("count", std::to_string(node.store.block_count(transaction)));
	response_l.put("unchecked", std::to_string(node.store.unchecked_count(transaction)));
	response(response_l);
}

void czr::rpc_handler::send()
{
	if (!rpc.config.enable_control)
		error_response(response, "RPC control is disabled");

	std::string from_text(request.get<std::string>("from"));
	czr::account from;
	auto error(from.decode_account(from_text));
	if (error)
	{
		error_response(response, "Invalid from account");
		return;
	}

	if(!node.key_manager.exists(from))
	{
		error_response(response, "From account not found");
		return;
	}

	std::string to_text(request.get<std::string>("to"));
	czr::account to;
	error = to.decode_account(to_text);
	if (error)
	{
		error_response(response, "Invalid to account");
		return;
	}

	std::string amount_text(request.get<std::string>("amount"));
	czr::amount amount;
	error = amount.decode_dec(amount_text);
	if (error)
	{
		error_response(response, "Invalid amount format");
		return;
	}

	std::string data_text(request.get<std::string>("data"));
	dev::bytes data;
	error = czr::hex_to_bytes(data_text, data);
	if (error)
	{
		error_response(response, "Invalid data");
		return;
	}
	if (data.size() > czr::max_data_size)
	{
		error_response(response, "Data size to large");
		return;
	}

	std::string password_text(request.get<std::string>("password"));

	boost::optional<std::string> send_id(request.get_optional<std::string>("id"));
	auto rpc_l(shared_from_this());
	auto response_a(response);
	node.wallet.send_async(from, to, amount.number(), data, password_text, [from, response_a](czr::send_result result) {
		switch (result.code)
		{
		case czr::send_result_codes::ok:
		{
			czr::uint256_union hash(result.block->hash());
			boost::property_tree::ptree response_l;
			response_l.put("block", hash.to_string());
			response_a(response_l);
			break;
		}
		case czr::send_result_codes::from_not_exists:
			error_response(response_a, "Account not exists, " + from.to_account());
			break;
		case czr::send_result_codes::account_locked:
			error_response(response_a, "Account locked");
			break;
		case czr::send_result_codes::wrong_password:
			error_response(response_a, "Wrong password");
			break;
		case czr::send_result_codes::insufficient_balance:
			error_response(response_a, "Insufficient balance");
			break;
		case czr::send_result_codes::data_size_too_large:
			error_response(response_a, "Data size to large");
			break;
		case czr::send_result_codes::validate_error:
			error_response(response_a, "Generate block fail, please retry later");
		case czr::send_result_codes::error:
			error_response(response_a, "Send block error");
			break;
		default:
			error_response(response_a, "Unknown error");
			break;
		}
	}, send_id);
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
	response_l.put("version", STR(CANONCHAIN_VERSION));
	response_l.put("rpc_version", "1");
	response_l.put("store_version", std::to_string(node.store_version()));
	response(response_l);
}
void czr::rpc_handler::witness_set()
{
	if (!rpc.config.enable_control)
	{
		error_response(response, "RPC control is disabled");
		return;
	}

	boost::optional<boost::property_tree::ptree> opwin(request.get_child_optional("witness_list"));
	if (!opwin)
	{
		error_response(response, "Not found witness_list");
		return;
	}
	//check witness_list
	std::vector<czr::account> vecwin;
	bool error(false);
	for (auto i : *opwin)
	{
		czr::account acco;
		std::string win_text = i.second.data();
		error = acco.decode_account(win_text);
		if (error)
		{
			error_response(response, "Bad from witness_list");
			return;
		}
		auto it = std::find(vecwin.begin(), vecwin.end(), acco);
		if (it != vecwin.end())
		{
			error_response(response, "Has same witness in witness_list");
			return;
		}
		vecwin.push_back(acco);
	}

	if (vecwin.size() != 12)
	{
		error_response(response, "Witness_list not equal 12");
		return;
	}
	
	//asc sort
	std::sort(vecwin.begin(), vecwin.end());
	
	//store 
	czr::transaction        transaction(node.store.environment, nullptr, true);;
	czr::witness_list_info  wl_info(vecwin);
	node.ledger.witness_list_put(transaction, wl_info);
	
	//response
	boost::property_tree::ptree response_l;
	response_l.put("witness_list store", " success");
	response(response_l);

}
void czr::rpc_handler::witness_list()
{
	czr::witness_list_info  wl_infoget;
	czr::transaction        transaction(node.store.environment, nullptr, false);;
	node.ledger.witness_list_get(transaction, wl_infoget);
	boost::property_tree::ptree response_l;
	boost::property_tree::ptree witness_list;
	for (auto i: wl_infoget.witness_list)
	{
		boost::property_tree::ptree entry;
		entry.put("", i.to_account());
		witness_list.push_back(std::make_pair("", entry));
	}
	response_l.add_child("witness_list", witness_list);
	response(response_l);
}


czr::rpc_connection::rpc_connection(czr::node & node_a, czr::rpc & rpc_a) :
	node(node_a.shared()),
	rpc(rpc_a),
	socket(node_a.io_service)
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

		bool handled = false;
		if (action == "account_create")
		{
			account_create();
			request.erase("password");
			reprocess_body(body, request);
			handled = true;
		}
		else if (action == "account_remove")
		{
			account_remove();
			request.erase("password");
			reprocess_body(body, request);
			handled = true;
		}
		else if (action == "account_unlock")
		{
			account_unlock();
			request.erase("password");
			reprocess_body(body, request);
			handled = true;
		}
		else if (action == "account_password_change")
		{
			account_password_change();
			request.erase("old_password");
			request.erase("new_password");
			reprocess_body(body, request);
			handled = true;
		}
		else if (action == "send")
		{
			send();
			request.erase("password");
			reprocess_body(body, request);
			handled = true;
		}

		if (handled)
			return;

		if (node.config.logging.log_rpc())
		{
			BOOST_LOG(node.log) << body;
		}
		if (action == "account_list")
		{
			account_list();
		}
		else if (action == "account_validate")
		{
			account_validate();
		}
		else if (action == "account_lock")
		{
			account_lock();
		}
		else if (action == "account_export")
		{
			account_export();
		}

		else if (action == "account_import")
		{
			account_import();
		}

		else if (action == "account_balance")
		{
			account_balance();
		}
		else if (action == "accounts_balances")
		{
			accounts_balances();
		}
		else if (action == "account_block_count")
		{
			account_block_count();
		}
		else if (action == "accounts_frontiers")
		{
			accounts_frontiers();
		}
		else if (action == "block")
		{
			block();
		}
		else if (action == "blocks")
		{
			blocks();
		}
		else if (action == "block_count")
		{
			block_count();
		}

		else if (action == "stop")
		{
			stop();
		}
		else if (action == "version")
		{
			version();
		}

		else if (action == "witness_set")
		{
			witness_set();
		}
		else if (action == "witness_list")
		{
			witness_list();
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
