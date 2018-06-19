#include <czr/node/node.hpp>
#include <czr/node/common.hpp>
#include <czr/node/rpc.hpp>
#include <czr/genesis.hpp>

#include <algorithm>
#include <future>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_set>

#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <ed25519-donna/ed25519.h>

std::chrono::seconds constexpr czr::node::period;
std::chrono::seconds constexpr czr::node::cutoff;
std::chrono::minutes constexpr czr::node::backup_interval;

bool czr::operation::operator> (czr::operation const & other_a) const
{
	return wakeup > other_a.wakeup;
}

czr::alarm::alarm(boost::asio::io_service & service_a) :
	service(service_a),
	thread([this]() { run(); })
{
}

czr::alarm::~alarm()
{
	add(std::chrono::steady_clock::now(), nullptr);
	thread.join();
}

void czr::alarm::run()
{
	std::unique_lock<std::mutex> lock(mutex);
	auto done(false);
	while (!done)
	{
		if (!operations.empty())
		{
			auto & operation(operations.top());
			if (operation.function)
			{
				if (operation.wakeup <= std::chrono::steady_clock::now())
				{
					service.post(operation.function);
					operations.pop();
				}
				else
				{
					auto wakeup(operation.wakeup);
					condition.wait_until(lock, wakeup);
				}
			}
			else
			{
				done = true;
			}
		}
		else
		{
			condition.wait(lock);
		}
	}
}

void czr::alarm::add(std::chrono::steady_clock::time_point const & wakeup_a, std::function<void()> const & operation)
{
	std::lock_guard<std::mutex> lock(mutex);
	operations.push(czr::operation({ wakeup_a, operation }));
	condition.notify_all();
}

czr::logging::logging() :
	ledger_logging_value(false),
	ledger_duplicate_logging_value(false),
	network_logging_value(true),
	network_message_logging_value(false),
	network_packet_logging_value(false),
	network_keepalive_logging_value(false),
	node_lifetime_tracing_value(false),
	log_rpc_value(true),
	log_to_cerr_value(false),
	max_size(16 * 1024 * 1024),
	rotation_size(4 * 1024 * 1024),
	flush(true)
{
}

void czr::logging::init(boost::filesystem::path const & application_path_a)
{
	static std::atomic_flag logging_already_added = ATOMIC_FLAG_INIT;
	if (!logging_already_added.test_and_set())
	{
		boost::log::add_common_attributes();
		if (log_to_cerr())
		{
			boost::log::add_console_log(std::cerr, boost::log::keywords::format = "[%TimeStamp%]: %Message%");
		}
		boost::log::add_file_log(boost::log::keywords::target = application_path_a / "log", boost::log::keywords::file_name = application_path_a / "log" / "log_%Y-%m-%d_%H-%M-%S.%N.log", boost::log::keywords::rotation_size = rotation_size, boost::log::keywords::auto_flush = flush, boost::log::keywords::scan_method = boost::log::sinks::file::scan_method::scan_matching, boost::log::keywords::max_size = max_size, boost::log::keywords::format = "[%TimeStamp%]: %Message%");
	}
}

void czr::logging::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("version", "1");
	tree_a.put("ledger", ledger_logging_value);
	tree_a.put("ledger_duplicate", ledger_duplicate_logging_value);
	tree_a.put("network", network_logging_value);
	tree_a.put("network_message", network_message_logging_value);
	tree_a.put("network_packet", network_packet_logging_value);
	tree_a.put("network_keepalive", network_keepalive_logging_value);
	tree_a.put("node_lifetime_tracing", node_lifetime_tracing_value);
	tree_a.put("log_rpc", log_rpc_value);
	tree_a.put("log_to_cerr", log_to_cerr_value);
	tree_a.put("max_size", max_size);
	tree_a.put("rotation_size", rotation_size);
	tree_a.put("flush", flush);
}

bool czr::logging::upgrade_json(unsigned version_a, boost::property_tree::ptree & tree_a)
{
	auto result(false);
	return result;
}

bool czr::logging::deserialize_json(bool & upgraded_a, boost::property_tree::ptree & tree_a)
{
	auto result(false);
	try
	{
		auto version_l(tree_a.get_optional<std::string>("version"));
		if (!version_l)
		{
			tree_a.put("version", "1");
			version_l = "1";
			upgraded_a = true;
		}
		upgraded_a |= upgrade_json(std::stoull(version_l.get()), tree_a);
		ledger_logging_value = tree_a.get<bool>("ledger");
		ledger_duplicate_logging_value = tree_a.get<bool>("ledger_duplicate");
		network_logging_value = tree_a.get<bool>("network");
		network_message_logging_value = tree_a.get<bool>("network_message");
		network_packet_logging_value = tree_a.get<bool>("network_packet");
		network_keepalive_logging_value = tree_a.get<bool>("network_keepalive");
		node_lifetime_tracing_value = tree_a.get<bool>("node_lifetime_tracing");
		log_rpc_value = tree_a.get<bool>("log_rpc");
		log_to_cerr_value = tree_a.get<bool>("log_to_cerr");
		max_size = tree_a.get<uintmax_t>("max_size");
		rotation_size = tree_a.get<uintmax_t>("rotation_size", 4194304);
		flush = tree_a.get<bool>("flush", true);
	}
	catch (std::runtime_error const &)
	{
		result = true;
	}
	return result;
}

bool czr::logging::ledger_logging() const
{
	return ledger_logging_value;
}

bool czr::logging::ledger_duplicate_logging() const
{
	return ledger_logging() && ledger_duplicate_logging_value;
}

bool czr::logging::network_logging() const
{
	return network_logging_value;
}

bool czr::logging::network_message_logging() const
{
	return network_logging() && network_message_logging_value;
}

bool czr::logging::network_packet_logging() const
{
	return network_logging() && network_packet_logging_value;
}

bool czr::logging::network_keepalive_logging() const
{
	return network_logging() && network_keepalive_logging_value;
}

bool czr::logging::node_lifetime_tracing() const
{
	return node_lifetime_tracing_value;
}

bool czr::logging::log_rpc() const
{
	return network_logging() && log_rpc_value;
}

bool czr::logging::callback_logging() const
{
	return network_logging();
}

bool czr::logging::log_to_cerr() const
{
	return log_to_cerr_value;
}

czr::node_init::node_init() :
	error(false)
{
}

czr::node_config::node_config() :
	node_config(czr::logging())
{
}

czr::node_config::node_config(czr::logging const & logging_a) :
	logging(logging_a),
	password_fanout(1024),
	io_threads(std::max<unsigned>(4, std::thread::hardware_concurrency())),
	callback_port(0),
	lmdb_max_dbs(128)
{
}

void czr::node_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("version", "1");
	boost::property_tree::ptree logging_l;
	logging.serialize_json(logging_l);
	tree_a.add_child("logging", logging_l);
	tree_a.put("password_fanout", std::to_string(password_fanout));
	tree_a.put("io_threads", std::to_string(io_threads));
	tree_a.put("callback_address", callback_address);
	tree_a.put("callback_port", std::to_string(callback_port));
	tree_a.put("callback_target", callback_target);
	tree_a.put("lmdb_max_dbs", lmdb_max_dbs);
}

bool czr::node_config::deserialize_json(bool & upgraded_a, boost::property_tree::ptree & tree_a)
{
	auto result(false);
	try
	{
		auto version_l(tree_a.get_optional<std::string>("version"));
		if (!version_l)
		{
			tree_a.put("version", "1");
			version_l = "1";
			upgraded_a = true;
		}
		auto & logging_l(tree_a.get_child("logging"));
		auto password_fanout_l(tree_a.get<std::string>("password_fanout"));
		auto io_threads_l(tree_a.get<std::string>("io_threads"));
		callback_address = tree_a.get<std::string>("callback_address");
		auto callback_port_l(tree_a.get<std::string>("callback_port"));
		callback_target = tree_a.get<std::string>("callback_target");
		auto lmdb_max_dbs_l = tree_a.get<std::string>("lmdb_max_dbs");
		result |= parse_port(callback_port_l, callback_port);
		try
		{
			password_fanout = std::stoul(password_fanout_l);
			io_threads = std::stoul(io_threads_l);
			lmdb_max_dbs = std::stoi(lmdb_max_dbs_l);
			result |= logging.deserialize_json(upgraded_a, logging_l);
			result |= password_fanout < 16;
			result |= password_fanout > 1024 * 1024;
			result |= io_threads == 0;
		}
		catch (std::logic_error const &)
		{
			result = true;
		}
	}
	catch (std::runtime_error const &)
	{
		result = true;
	}
	return result;
}

czr::block_processor_item::block_processor_item(czr::joint joint_a) :
	joint(joint_a)
{
}

czr::block_processor::block_processor(czr::node & node_a) :
	stopped(false),
	idle(true),
	node(node_a)
{
}

czr::block_processor::~block_processor()
{
	stop();
}

void czr::block_processor::stop()
{
	std::lock_guard<std::mutex> lock(mutex);
	stopped = true;
	condition.notify_all();
}

void czr::block_processor::flush()
{
	std::unique_lock<std::mutex> lock(mutex);
	while (!stopped && (!blocks.empty() || !idle))
	{
		condition.wait(lock);
	}
}

void czr::block_processor::add(czr::block_processor_item const & item_a)
{
	std::lock_guard<std::mutex> lock(mutex);
	blocks.push_back(item_a);
	condition.notify_all();
}

void czr::block_processor::process_blocks()
{
	std::unique_lock<std::mutex> lock(mutex);
	while (!stopped)
	{
		if (!blocks.empty())
		{
			std::deque<czr::block_processor_item> blocks_processing;
			std::swap(blocks, blocks_processing);
			lock.unlock();
			process_receive_many(blocks_processing);
			// Let other threads get an opportunity to transaction lock
			std::this_thread::yield();
			lock.lock();
		}
		else
		{
			idle = true;
			condition.notify_all();
			condition.wait(lock);
			idle = false;
		}
	}
}

void czr::block_processor::process_receive_many(czr::block_processor_item const & item_a)
{
	std::deque<czr::block_processor_item> blocks_processing;
	blocks_processing.push_back(item_a);
	process_receive_many(blocks_processing);
}

void czr::block_processor::process_receive_many(std::deque<czr::block_processor_item> & blocks_processing)
{
	while (!blocks_processing.empty())
	{
		std::deque<std::pair<std::shared_ptr<czr::block>, czr::validate_result>> progress;
		{
			czr::transaction transaction(node.store.environment, nullptr, true);
			auto cutoff(std::chrono::steady_clock::now() + czr::transaction_timeout);
			while (!blocks_processing.empty() && std::chrono::steady_clock::now() < cutoff)
			{
				auto item(blocks_processing.front());
				auto block = item.joint.block;
				blocks_processing.pop_front();
				auto hash(block->hash());
				auto result(process_receive_one(transaction, item.joint));
				switch (result.code)
				{
					case czr::validate_result_codes::ok:
					{
						progress.push_back(std::make_pair(block, result));
					}
					case czr::validate_result_codes::old:
					{
						//todo:check unhandle_message db if any unhandle message can be process again;

						//auto cached(node.store.unchecked_get(transaction, hash));
						//for (auto i(cached.begin()), n(cached.end()); i != n; ++i)
						//{
						//	node.store.unchecked_del(transaction, hash, **i);
						//	blocks_processing.push_front(czr::block_processor_item(*i));
						//}
						//std::lock_guard<std::mutex> lock(node.gap_cache.mutex);
						//node.gap_cache.blocks.get<1>().erase(hash);
						break;
					}
					default:
						break;
				}
			}
		}

		for (auto & i : progress)
		{
			node.observers.blocks(i.first, i.second);
			if (i.second.amount > 0)
			{
				node.observers.account_balance(i.second.account, false);
			}
		}
	}
}

czr::validate_result czr::block_processor::process_receive_one(MDB_txn * transaction_a, czr::joint const & message)
{
	czr::validate_result result(node.validation->validate(transaction_a, message));

	switch (result.code)
	{
		case czr::validate_result_codes::ok:
		{
			node.chain->save_block(transaction_a, *message.block);

			if (node.config.logging.ledger_logging())
			{
				std::string block;
				message.block->serialize_json(block);
				BOOST_LOG(node.log) << boost::str(boost::format("Processing block %1% %2%") % message.block->hash().to_string() % block);
			}
			break;
		}
		case czr::validate_result_codes::old:
		{
			if (node.config.logging.ledger_duplicate_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Old for: %1%") % message.block->hash().to_string());
			}
			break;
		}
		case czr::validate_result_codes::missing_parents_and_previous:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Missing parents and previous for: %1%") % message.block->hash().to_string());
			}
			std::vector<block_hash> missing_parents_and_previous(result.missing_parents_and_previous);
			//todo: store message to unhandle_message db 
			//todo: to request missing parents_and_previous
			break;
		}
		case czr::validate_result_codes::missing_hash_tree_summary:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Missing hash tree summary for: %1%") % message.block->hash().to_string());
			}
			//todo:to request catchup
			break;
		}
		case czr::validate_result_codes::exec_timestamp_too_late:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Exec timestamp too late, block: %1%, exec_timestamp: %2%")
					% message.block->hash().to_string() % message.block->hashables.exec_timestamp);
			}

			//cache late message
			if (message.block->hashables.exec_timestamp < czr::seconds_since_epoch() + 600) //10 minutes
			{
				node.late_message_cache.add(message);
			}

			break;
		}
		case czr::validate_result_codes::invalid_block:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Invalid block: %1%, error message: %2%") % message.block->hash().to_string() % result.err_msg);
			}

			//cache invalid block
			node.invalid_block_cache.add(message.block->hash());
			break;
		}
		case czr::validate_result_codes::known_invalid_block:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Known invalid block: %1%") % message.block->hash().to_string());
			}
			break;
		}
		case czr::validate_result_codes::invalid_message:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Invalid message: %1%") % result.err_msg);
			}
			break;
		}
	}
	return result;
}

czr::node::node(czr::node_init & init_a, boost::asio::io_service & service_a, uint16_t peering_port_a, 
	boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::logging const & logging_a) :
	node(init_a, service_a, application_path_a, alarm_a, czr::node_config(logging_a))
{
}

czr::node::node(czr::node_init & init_a, boost::asio::io_service & service_a, 
	boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::node_config const & config_a) :
	service(service_a),
	config(config_a),
	alarm(alarm_a),
	store(init_a.error, application_path_a / "data.ldb", config_a.lmdb_max_dbs),
	gap_cache(*this),
	ledger(store),
	wallets(init_a.error, *this),
	application_path(application_path_a),
	warmed_up(0),
	validation(std::make_shared<czr::validation>(*this)),
	chain(std::make_shared<czr::chain>(*this, [](std::shared_ptr<czr::block> block_a){})),
	block_processor(*this),
	block_processor_thread([this]() { this->block_processor.process_blocks(); })
{
	wallets.observer = [this](bool active) {
		observers.wallet(active);
	};
	observers.blocks.add([this](std::shared_ptr<czr::block> block_a, czr::validate_result const & result_a) {
		if (this->block_arrival.recent(block_a->hash()))
		{
			auto node_l(shared_from_this());
			background([node_l, block_a, result_a]() {
				if (!node_l->config.callback_address.empty())
				{
					boost::property_tree::ptree event;
					event.add("account", result_a.account.to_account());
					event.add("hash", block_a->hash().to_string());
					std::string block_text;
					block_a->serialize_json(block_text);
					event.add("block", block_text);
					event.add("amount", result_a.amount.to_string_dec());
					std::stringstream ostream;
					boost::property_tree::write_json(ostream, event);
					ostream.flush();
					auto body(std::make_shared<std::string>(ostream.str()));
					auto address(node_l->config.callback_address);
					auto port(node_l->config.callback_port);
					auto target(std::make_shared<std::string>(node_l->config.callback_target));
					auto resolver(std::make_shared<boost::asio::ip::tcp::resolver>(node_l->service));
					resolver->async_resolve(boost::asio::ip::tcp::resolver::query(address, std::to_string(port)), [node_l, address, port, target, body, resolver](boost::system::error_code const & ec, boost::asio::ip::tcp::resolver::iterator i_a) {
						if (!ec)
						{
							for (auto i(i_a), n(boost::asio::ip::tcp::resolver::iterator{}); i != n; ++i)
							{
								auto sock(std::make_shared<boost::asio::ip::tcp::socket>(node_l->service));
								sock->async_connect(i->endpoint(), [node_l, target, body, sock, address, port](boost::system::error_code const & ec) {
									if (!ec)
									{
										auto req(std::make_shared<boost::beast::http::request<boost::beast::http::string_body>>());
										req->method(boost::beast::http::verb::post);
										req->target(*target);
										req->version(11);
										req->insert(boost::beast::http::field::host, address);
										req->insert(boost::beast::http::field::content_type, "application/json");
										req->body() = *body;
										//req->prepare (*req);
										//boost::beast::http::prepare(req);
										req->prepare_payload();
										boost::beast::http::async_write(*sock, *req, [node_l, sock, address, port, req](boost::system::error_code const & ec, size_t bytes_transferred) {
											if (!ec)
											{
												auto sb(std::make_shared<boost::beast::flat_buffer>());
												auto resp(std::make_shared<boost::beast::http::response<boost::beast::http::string_body>>());
												boost::beast::http::async_read(*sock, *sb, *resp, [node_l, sb, resp, sock, address, port](boost::system::error_code const & ec, size_t bytes_transferred) {
													if (!ec)
													{
														if (resp->result() == boost::beast::http::status::ok)
														{
														}
														else
														{
															if (node_l->config.logging.callback_logging())
															{
																BOOST_LOG(node_l->log) << boost::str(boost::format("Callback to %1%:%2% failed with status: %3%") % address % port % resp->result());
															}
														}
													}
													else
													{
														if (node_l->config.logging.callback_logging())
														{
															BOOST_LOG(node_l->log) << boost::str(boost::format("Unable complete callback: %1%:%2% %3%") % address % port % ec.message());
														}
													};
												});
											}
											else
											{
												if (node_l->config.logging.callback_logging())
												{
													BOOST_LOG(node_l->log) << boost::str(boost::format("Unable to send callback: %1%:%2% %3%") % address % port % ec.message());
												}
											}
										});
									}
									else
									{
										if (node_l->config.logging.callback_logging())
										{
											BOOST_LOG(node_l->log) << boost::str(boost::format("Unable to connect to callback address: %1%:%2%, %3%") % address % port % ec.message());
										}
									}
								});
							}
						}
						else
						{
							if (node_l->config.logging.callback_logging())
							{
								BOOST_LOG(node_l->log) << boost::str(boost::format("Error resolving callback: %1%:%2%, %3%") % address % port % ec.message());
							}
						}
					});
				}
			});
		}
	});

	BOOST_LOG(log) << "Node starting, version: " << CANONCHAIN_VERSION_MAJOR << "." << CANONCHAIN_VERSION_MINOR;
	if (!init_a.error)
	{
		if (config.logging.node_lifetime_tracing())
		{
			BOOST_LOG(log) << "Constructing node";
		}

		try
		{
			czr::transaction transaction(store.environment, nullptr, true);
			czr::genesis::try_initialize(transaction, store);
		}
		catch (const std::runtime_error & e)
		{
			BOOST_LOG(log) << boost::str(boost::format("Init genesis error: %1%") % e.what());
			init_a.error = true;
		}
	}
}

czr::node::~node()
{
	if (config.logging.node_lifetime_tracing())
	{
		BOOST_LOG(log) << "Destructing node";
	}
	stop();
}

bool czr::node::copy_with_compaction(boost::filesystem::path const & destination_file)
{
	return !mdb_env_copy2(store.environment.environment,
		destination_file.string().c_str(), MDB_CP_COMPACT);
}

czr::gap_cache::gap_cache(czr::node & node_a) :
	node(node_a)
{
}

void czr::gap_cache::add(MDB_txn * transaction_a, std::shared_ptr<czr::block> block_a)
{
	auto hash(block_a->hash());
	std::lock_guard<std::mutex> lock(mutex);
	auto existing(blocks.get<1>().find(hash));
	if (existing != blocks.get<1>().end())
	{
		blocks.get<1>().modify(existing, [](czr::gap_information & info) {
			info.arrival = std::chrono::steady_clock::now();
		});
	}
	else
	{
		blocks.insert({ std::chrono::steady_clock::now(), hash });
		if (blocks.size() > max)
		{
			blocks.get<0>().erase(blocks.get<0>().begin());
		}
	}
}

void czr::gap_cache::purge_old()
{
	auto cutoff(std::chrono::steady_clock::now() - std::chrono::seconds(10));
	std::lock_guard<std::mutex> lock(mutex);
	auto done(false);
	while (!done && !blocks.empty())
	{
		auto first(blocks.get<1>().begin());
		if (first->arrival < cutoff)
		{
			blocks.get<1>().erase(first);
		}
		else
		{
			done = true;
		}
	}
}

void czr::node::process_active(czr::joint const & message)
{
	block_arrival.add(message.block->hash());
	block_processor.add(message);
}

void czr::node::start()
{
	ongoing_store_flush();
	ongoing_retry_late_message();
	backup_wallet();
	observers.started();
}

void czr::node::stop()
{
	BOOST_LOG(log) << "Node stopping";
	block_processor.stop();
	wallets.stop();
	if (block_processor_thread.joinable())
	{
		block_processor_thread.join();
	}
}

czr::block_hash czr::node::latest(czr::account const & account_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	return ledger.latest(transaction, account_a);
}

czr::uint128_t czr::node::balance(czr::account const & account_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	return ledger.account_balance(transaction, account_a);
}

std::unique_ptr<czr::block> czr::node::block(czr::block_hash const & hash_a)
{
	czr::transaction transaction(store.environment, nullptr, false);
	return store.block_get(transaction, hash_a);
}

void czr::node::ongoing_store_flush()
{
	{
		czr::transaction transaction(store.environment, nullptr, true);
		store.flush(transaction);
	}
	std::weak_ptr<czr::node> node_w(shared_from_this());
	alarm.add(std::chrono::steady_clock::now() + std::chrono::seconds(5), [node_w]() {
		if (auto node_l = node_w.lock())
		{
			node_l->ongoing_store_flush();
		}
	});
}

void czr::node::ongoing_retry_late_message()
{
	auto late_msg_info_list(late_message_cache.purge_list_ealier_than(czr::seconds_since_epoch()));
	for (auto info : late_msg_info_list)
		block_processor.add(czr::block_processor_item(info.message));

	std::weak_ptr<czr::node> node_w(shared_from_this());
	alarm.add(std::chrono::steady_clock::now() + std::chrono::seconds(5), [node_w]() {
		if (auto node_l = node_w.lock())
		{
			node_l->ongoing_retry_late_message();
		}
	});
}

void czr::node::backup_wallet()
{
	czr::transaction transaction(store.environment, nullptr, false);
	for (auto i(wallets.items.begin()), n(wallets.items.end()); i != n; ++i)
	{
		auto backup_path(application_path / "backup");
		boost::filesystem::create_directories(backup_path);
		i->second->store.write_backup(transaction, backup_path / (i->first.to_string() + ".json"));
	}
	auto this_l(shared());
	alarm.add(std::chrono::steady_clock::now() + backup_interval, [this_l]() {
		this_l->backup_wallet();
	});
}

void czr::block_arrival::add(czr::block_hash const & hash_a)
{
	std::lock_guard<std::mutex> lock(mutex);
	auto now(std::chrono::steady_clock::now());
	arrival.insert(czr::block_arrival_info{ now, hash_a });
}

bool czr::block_arrival::recent(czr::block_hash const & hash_a)
{
	std::lock_guard<std::mutex> lock(mutex);
	auto now(std::chrono::steady_clock::now());
	while (!arrival.empty() && arrival.begin()->arrival + std::chrono::seconds(60) < now)
	{
		arrival.erase(arrival.begin());
	}
	return arrival.get<1>().find(hash_a) != arrival.get<1>().end();
}

std::shared_ptr<czr::node> czr::node::shared()
{
	return shared_from_this();
}

int czr::node::store_version()
{
	czr::transaction transaction(store.environment, nullptr, false);
	return store.version_get(transaction);
}

czr::thread_runner::thread_runner(boost::asio::io_service & service_a, unsigned service_threads_a)
{
	for (auto i(0); i < service_threads_a; ++i)
	{
		threads.push_back(std::thread([&service_a]() {
			try
			{
				service_a.run();
			}
			catch (std::exception const & e)
			{
				auto msg = e.what();
			}
			catch (...)
			{
				assert(false && "Unhandled service exception");
			}
		}));
	}
}

czr::thread_runner::~thread_runner()
{
	join();
}

void czr::thread_runner::join()
{
	for (auto & i : threads)
	{
		if (i.joinable())
		{
			i.join();
		}
	}
}

void czr::add_node_options(boost::program_options::options_description & description_a)
{
	// clang-format off
	description_a.add_options()
		("account_create", "Insert next deterministic key in to <wallet>")
		("account_get", "Get account number for the <key>")
		("account_key", "Get the public key for <account>")
		("vacuum", "Compact database. If data_path is missing, the database in data directory is compacted.")
		("snapshot", "Compact database and create snapshot, functions similar to vacuum but does not replace the existing database")
		("data_path", boost::program_options::value<std::string>(), "Use the supplied path as the data directory")
		("key_create", "Generates a adhoc random keypair and prints it to stdout")
		("key_expand", "Derive public key and account number from <key>")
		("wallet_add_adhoc", "Insert <key> in to <wallet>")
		("wallet_create", "Creates a new wallet and prints the ID")
		("wallet_change_seed", "Changes seed for <wallet> to <key>")
		("wallet_decrypt_unsafe", "Decrypts <wallet> using <password>, !!THIS WILL PRINT YOUR PRIVATE KEY TO STDOUT!!")
		("wallet_destroy", "Destroys <wallet> and all keys it contains")
		("wallet_import", "Imports keys in <file> using <password> in to <wallet>")
		("wallet_list", "Dumps wallet IDs and public keys")
		("wallet_remove", "Remove <account> from <wallet>")
		("account", boost::program_options::value<std::string>(), "Defines <account> for other commands")
		("file", boost::program_options::value<std::string>(), "Defines <file> for other commands")
		("key", boost::program_options::value<std::string>(), "Defines the <key> for other commands, hex")
		("password", boost::program_options::value<std::string>(), "Defines <password> for other commands")
		("wallet", boost::program_options::value<std::string>(), "Defines <wallet> for other commands");
	// clang-format on
}

bool czr::handle_node_options(boost::program_options::variables_map & vm)
{
	auto result(false);
	boost::filesystem::path data_path = vm.count("data_path") ? boost::filesystem::path(vm["data_path"].as<std::string>()) : czr::working_path();
	if (vm.count("account_create"))
	{
		if (vm.count("wallet") == 1)
		{
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				std::string password;
				if (vm.count("password") > 0)
				{
					password = vm["password"].as<std::string>();
				}
				inactive_node node(data_path);
				auto wallet(node.node->wallets.open(wallet_id));
				if (wallet != nullptr)
				{
					if (!wallet->enter_password(password))
					{
						czr::transaction transaction(wallet->store.environment, nullptr, true);
						auto pub(wallet->store.deterministic_insert(transaction));
						std::cout << boost::str(boost::format("Account: %1%\n") % pub.to_account());
					}
					else
					{
						std::cerr << "Invalid password\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "Wallet doesn't exist\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_add command requires one <wallet> option and one <key> option and optionally one <password> option\n";
			result = true;
		}
	}
	else if (vm.count("account_get") > 0)
	{
		if (vm.count("key") == 1)
		{
			czr::uint256_union pub;
			pub.decode_hex(vm["key"].as<std::string>());
			std::cout << "Account: " << pub.to_account() << std::endl;
		}
		else
		{
			std::cerr << "account comand requires one <key> option\n";
			result = true;
		}
	}
	else if (vm.count("account_key") > 0)
	{
		if (vm.count("account") == 1)
		{
			czr::uint256_union account;
			account.decode_account(vm["account"].as<std::string>());
			std::cout << "Hex: " << account.to_string() << std::endl;
		}
		else
		{
			std::cerr << "account_key command requires one <account> option\n";
			result = true;
		}
	}
	else if (vm.count("vacuum") > 0)
	{
		try
		{
			auto vacuum_path = data_path / "vacuumed.ldb";
			auto source_path = data_path / "data.ldb";
			auto backup_path = data_path / "backup.vacuum.ldb";

			std::cout << "Vacuuming database copy in " << data_path << std::endl;
			std::cout << "This may take a while..." << std::endl;

			// Scope the node so the mdb environment gets cleaned up properly before
			// the original file is replaced with the vacuumed file.
			bool success = false;
			{
				inactive_node node(data_path);
				success = node.node->copy_with_compaction(vacuum_path);
			}

			if (success)
			{
				// Note that these throw on failure
				std::cout << "Finalizing" << std::endl;
				boost::filesystem::remove(backup_path);
				boost::filesystem::rename(source_path, backup_path);
				boost::filesystem::rename(vacuum_path, source_path);
				std::cout << "Vacuum completed" << std::endl;
			}
		}
		catch (const boost::filesystem::filesystem_error & ex)
		{
			std::cerr << "Vacuum failed during a file operation: " << ex.what() << std::endl;
		}
		catch (...)
		{
			std::cerr << "Vacuum failed" << std::endl;
		}
	}
	else if (vm.count("snapshot"))
	{
		try
		{
			boost::filesystem::path data_path = vm.count("data_path") ? boost::filesystem::path(vm["data_path"].as<std::string>()) : czr::working_path();

			auto source_path = data_path / "data.ldb";
			auto snapshot_path = data_path / "snapshot.ldb";

			std::cout << "Database snapshot of " << source_path << " to " << snapshot_path << " in progress" << std::endl;
			std::cout << "This may take a while..." << std::endl;

			bool success = false;
			{
				inactive_node node(data_path);
				success = node.node->copy_with_compaction(snapshot_path);
			}
			if (success)
			{
				std::cout << "Snapshot completed, This can be found at " << snapshot_path << std::endl;
			}
		}
		catch (const boost::filesystem::filesystem_error & ex)
		{
			std::cerr << "Snapshot failed during a file operation: " << ex.what() << std::endl;
		}
		catch (...)
		{
			std::cerr << "Snapshot Failed" << std::endl;
		}
	}
	else if (vm.count("key_create"))
	{
		czr::keypair pair;
		std::cout << "Private: " << pair.prv.data.to_string() << std::endl
			<< "Public: " << pair.pub.to_string() << std::endl
			<< "Account: " << pair.pub.to_account() << std::endl;
	}
	else if (vm.count("key_expand"))
	{
		if (vm.count("key") == 1)
		{
			czr::uint256_union prv;
			prv.decode_hex(vm["key"].as<std::string>());
			czr::uint256_union pub;
			ed25519_publickey(prv.bytes.data(), pub.bytes.data());
			std::cout << "Private: " << prv.to_string() << std::endl
				<< "Public: " << pub.to_string() << std::endl
				<< "Account: " << pub.to_account() << std::endl;
		}
		else
		{
			std::cerr << "key_expand command requires one <key> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_add_adhoc"))
	{
		if (vm.count("wallet") == 1 && vm.count("key") == 1)
		{
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				std::string password;
				if (vm.count("password") > 0)
				{
					password = vm["password"].as<std::string>();
				}
				inactive_node node(data_path);
				auto wallet(node.node->wallets.open(wallet_id));
				if (wallet != nullptr)
				{
					if (!wallet->enter_password(password))
					{
						czr::raw_key key;
						if (!key.data.decode_hex(vm["key"].as<std::string>()))
						{
							czr::transaction transaction(wallet->store.environment, nullptr, true);
							wallet->store.insert_adhoc(transaction, key);
						}
						else
						{
							std::cerr << "Invalid key\n";
							result = true;
						}
					}
					else
					{
						std::cerr << "Invalid password\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "Wallet doesn't exist\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_add command requires one <wallet> option and one <key> option and optionally one <password> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_change_seed"))
	{
		if (vm.count("wallet") == 1 && vm.count("key") == 1)
		{
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				std::string password;
				if (vm.count("password") > 0)
				{
					password = vm["password"].as<std::string>();
				}
				inactive_node node(data_path);
				auto wallet(node.node->wallets.open(wallet_id));
				if (wallet != nullptr)
				{
					if (!wallet->enter_password(password))
					{
						czr::raw_key key;
						if (!key.data.decode_hex(vm["key"].as<std::string>()))
						{
							czr::transaction transaction(wallet->store.environment, nullptr, true);
							wallet->change_seed(transaction, key);
						}
						else
						{
							std::cerr << "Invalid key\n";
							result = true;
						}
					}
					else
					{
						std::cerr << "Invalid password\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "Wallet doesn't exist\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_add command requires one <wallet> option and one <key> option and optionally one <password> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_create"))
	{
		inactive_node node(data_path);
		czr::keypair key;
		std::cout << key.pub.to_string() << std::endl;
		auto wallet(node.node->wallets.create(key.pub));
		wallet->enter_initial_password();
	}
	else if (vm.count("wallet_decrypt_unsafe"))
	{
		if (vm.count("wallet") == 1)
		{
			std::string password;
			if (vm.count("password") == 1)
			{
				password = vm["password"].as<std::string>();
			}
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				inactive_node node(data_path);
				auto existing(node.node->wallets.items.find(wallet_id));
				if (existing != node.node->wallets.items.end())
				{
					if (!existing->second->enter_password(password))
					{
						czr::transaction transaction(existing->second->store.environment, nullptr, false);
						czr::raw_key seed;
						existing->second->store.seed(seed, transaction);
						std::cout << boost::str(boost::format("Seed: %1%\n") % seed.data.to_string());
						for (auto i(existing->second->store.begin(transaction)), m(existing->second->store.end()); i != m; ++i)
						{
							czr::account account(i->first.uint256());
							czr::raw_key key;
							auto error(existing->second->store.fetch(transaction, account, key));
							assert(!error);
							std::cout << boost::str(boost::format("Pub: %1% Prv: %2%\n") % account.to_account() % key.data.to_string());
						}
					}
					else
					{
						std::cerr << "Invalid password\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "Wallet doesn't exist\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_decrypt_unsafe requires one <wallet> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_destroy"))
	{
		if (vm.count("wallet") == 1)
		{
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				inactive_node node(data_path);
				if (node.node->wallets.items.find(wallet_id) != node.node->wallets.items.end())
				{
					node.node->wallets.destroy(wallet_id);
				}
				else
				{
					std::cerr << "Wallet doesn't exist\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_destroy requires one <wallet> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_import"))
	{
		if (vm.count("file") == 1)
		{
			std::string filename(vm["file"].as<std::string>());
			std::ifstream stream;
			stream.open(filename.c_str());
			if (!stream.fail())
			{
				std::stringstream contents;
				contents << stream.rdbuf();
				std::string password;
				if (vm.count("password") == 1)
				{
					password = vm["password"].as<std::string>();
				}
				if (vm.count("wallet") == 1)
				{
					czr::uint256_union wallet_id;
					if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
					{
						inactive_node node(data_path);
						auto existing(node.node->wallets.items.find(wallet_id));
						if (existing != node.node->wallets.items.end())
						{
							if (!existing->second->import(contents.str(), password))
							{
								result = false;
							}
							else
							{
								std::cerr << "Unable to import wallet\n";
								result = true;
							}
						}
						else
						{
							std::cerr << "Wallet doesn't exist\n";
							result = true;
						}
					}
					else
					{
						std::cerr << "Invalid wallet id\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "wallet_import requires one <wallet> option\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Unable to open <file>\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_import requires one <file> option\n";
			result = true;
		}
	}
	else if (vm.count("wallet_list"))
	{
		inactive_node node(data_path);
		for (auto i(node.node->wallets.items.begin()), n(node.node->wallets.items.end()); i != n; ++i)
		{
			std::cout << boost::str(boost::format("Wallet ID: %1%\n") % i->first.to_string());
			czr::transaction transaction(i->second->store.environment, nullptr, false);
			for (auto j(i->second->store.begin(transaction)), m(i->second->store.end()); j != m; ++j)
			{
				std::cout << czr::uint256_union(j->first.uint256()).to_account() << '\n';
			}
		}
	}
	else if (vm.count("wallet_remove"))
	{
		if (vm.count("wallet") == 1 && vm.count("account") == 1)
		{
			inactive_node node(data_path);
			czr::uint256_union wallet_id;
			if (!wallet_id.decode_hex(vm["wallet"].as<std::string>()))
			{
				auto wallet(node.node->wallets.items.find(wallet_id));
				if (wallet != node.node->wallets.items.end())
				{
					czr::account account_id;
					if (!account_id.decode_account(vm["account"].as<std::string>()))
					{
						czr::transaction transaction(wallet->second->store.environment, nullptr, true);
						auto account(wallet->second->store.find(transaction, account_id));
						if (account != wallet->second->store.end())
						{
							wallet->second->store.erase(transaction, account_id);
						}
						else
						{
							std::cerr << "Account not found in wallet\n";
							result = true;
						}
					}
					else
					{
						std::cerr << "Invalid account id\n";
						result = true;
					}
				}
				else
				{
					std::cerr << "Wallet not found\n";
					result = true;
				}
			}
			else
			{
				std::cerr << "Invalid wallet id\n";
				result = true;
			}
		}
		else
		{
			std::cerr << "wallet_remove command requires one <wallet> and one <account> option\n";
			result = true;
		}
	}
	else
	{
		result = true;
	}
	return result;
}

czr::inactive_node::inactive_node(boost::filesystem::path const & path) :
	path(path),
	service(boost::make_shared<boost::asio::io_service>()),
	alarm(*service)
{
	boost::filesystem::create_directories(path);
	logging.init(path);
	node = std::make_shared<czr::node>(init, *service, 24000, path, alarm, logging);
}

czr::inactive_node::~inactive_node()
{
	node->stop();
}

czr::late_message_info::late_message_info(czr::joint const & message_a) :
	message(message_a),
	timestamp(message_a.block->hashables.exec_timestamp),
	hash(message_a.block->hash())
{
}

czr::late_message_cache::late_message_cache(size_t const & capacity_a) :
	capacity(capacity_a)
{
}

void czr::late_message_cache::add(czr::late_message_info const & info)
{
	auto result(container.insert(info));
	if (result.second && container.size() > capacity)
	{
		auto last(container.get<1>().rbegin().base());
		container.get<1>().erase(last);
	}
}

std::vector<czr::late_message_info> czr::late_message_cache::purge_list_ealier_than(uint64_t const & timestamp)
{
	std::vector<czr::late_message_info> result;
	auto upper(container.get<1>().upper_bound(timestamp));//first element large than timestamp
	for(auto i(container.get<1>().begin()); i != upper; i++)
	{
		result.push_back(*i);
		container.get<1>().erase(i);
	}
	return result;
}

czr::invalid_block_cache::invalid_block_cache(size_t const & capacity_a):
	capacity(capacity_a)
{
}

void czr::invalid_block_cache::add(czr::block_hash const & hash_a)
{
	auto result(container.push_front(hash_a));
	if (result.second && container.size() > capacity)
	{
		container.pop_back();
	}
}

bool czr::invalid_block_cache::contains(czr::block_hash const & hash_a)
{
	return container.get<1>().find(hash_a) != container.get<1>().end();
}
