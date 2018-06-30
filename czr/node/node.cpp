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

//#include <conio.h>  //password
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

	boost::property_tree::ptree p2p_l;
	p2p.serialize_json(p2p_l);
	tree_a.add_child("p2p", p2p_l);

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
		auto & p2p_l(tree_a.get_child("p2p"));
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
			result |= p2p.deserialize_json(upgraded_a, p2p_l);
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
	if (item_a.is_local())
		blocks.push_front(item_a);
	else
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

void czr::block_processor::process_receive_many(std::deque<czr::block_processor_item> & blocks_processing)
{
	while (!blocks_processing.empty())
	{
		{
			czr::transaction transaction(node.store.environment, nullptr, true);
			auto cutoff(std::chrono::steady_clock::now() + czr::transaction_timeout);
			try
			{
				while (!blocks_processing.empty() && std::chrono::steady_clock::now() < cutoff)
				{
					auto item(blocks_processing.front());
					blocks_processing.pop_front();
					auto result(process_receive_one(transaction, item));
					switch (result.code)
					{
					case czr::validate_result_codes::ok:
					case czr::validate_result_codes::old:
					{
						auto block = item.joint.block;
						auto b_hash(block->hash());

						std::list<czr::block_hash> unhandleds;
						node.store.dependency_unhandled_get(transaction, b_hash, unhandleds);
						for (czr::block_hash unhandled_hash : unhandleds)
						{
							node.store.dependency_unhandled_del(transaction, b_hash, unhandled_hash);
							node.store.unhandled_dependency_del(transaction, unhandled_hash, b_hash);

							bool dependency_exists(node.store.unhandled_dependency_exists(transaction, unhandled_hash));
							if (!dependency_exists)
							{
								dev::bytes b;
								node.store.unhandled_get(transaction, unhandled_hash, b);
								node.store.unhandled_del(transaction, unhandled_hash);
								bool error(false);
								czr::block_processor_item item(error, dev::RLP(b));
								assert(!error);
								if (!error)
									blocks_processing.push_front(item);
							}
						}
						break;
					}
					//------
					case czr::validate_result_codes::invalid_block:
					case czr::validate_result_codes::known_invalid_block:
					{
						auto block = item.joint.block;
						auto dependency_hash(block->hash());

						std::list<czr::block_hash> unhandleds;
						node.store.dependency_unhandled_get(transaction, dependency_hash, unhandleds);
						for (czr::block_hash unhandled_hash : unhandleds)
						{
							node.store.dependency_unhandled_del(transaction, dependency_hash, unhandled_hash);
							node.store.unhandled_dependency_del(transaction, unhandled_hash, dependency_hash);
						    node.store.unhandled_del(transaction, unhandled_hash);	
						}
						break;
					}
					default:
						break;
					}
				}
			}
			catch (std::exception const & e)
			{
				BOOST_LOG(node.log) << "Block process error: " << e.what();
				transaction.abort();
				throw;
			}
		}
	}
}

czr::validate_result czr::block_processor::process_receive_one(MDB_txn * transaction_a, czr::block_processor_item const & item)
{
	czr::joint_message const & joint(item.joint);
	czr::validate_result result(node.validation->validate(transaction_a, item.joint));

	switch (result.code)
	{
		case czr::validate_result_codes::ok:
		{
			node.chain->save_block(transaction_a, *joint.block);

			//send block
			node.capability->send_block(joint);

			bool is_catch_up(false);  //todo: get is_catch_up;
			if (node.m_witness && !is_catch_up)
			{
				auto node_l(node.shared());
				node.background([node_l]() {
					//if I am a witness, do work
					node_l->m_witness->check_and_witness();
				});
			}
			if (node.config.logging.ledger_logging())
			{
				std::string const & json(joint.block->to_json());
				BOOST_LOG(node.log) << boost::str(boost::format("Processing block %1% %2%") % joint.block->hash().to_string() % json);
			}
			break;
		}
		case czr::validate_result_codes::old:
		{
			if (node.config.logging.ledger_duplicate_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Old for: %1%") % joint.block->hash().to_string());
			}
			break;
		}
		case czr::validate_result_codes::missing_parents_and_previous:
		{
			assert(!item.is_local());

			czr::block_hash b_hash(joint.block->hash());
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Missing parents and previous for: %1%") % b_hash.to_string());
			}

			dev::bytes b;
			{
				dev::RLPStream s;
				item.stream_RLP(s);
				s.swapOut(b);
			}
			node.store.unhandled_put(transaction_a, b_hash, b);
			std::list<block_hash> missing_parents_and_previous(result.missing_parents_and_previous);

			uint64_t dead_time(seconds_since_epoch());
			node.store.deadtime_unhandle_put(transaction_a,dead_time, b_hash);
			for (czr::block_hash p_missing : missing_parents_and_previous)
			{
				node.store.unhandled_dependency_put(transaction_a, b_hash, p_missing);
				node.store.dependency_unhandled_put(transaction_a, p_missing, b_hash);
			}
			//todo: to request missing parents_and_previous
			break;
		}
		case czr::validate_result_codes::missing_hash_tree_summary:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Missing hash tree summary for: %1%") % joint.block->hash().to_string());
			}
			//todo:to request catchup
			break;
		}
		case czr::validate_result_codes::exec_timestamp_too_late:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Exec timestamp too late, block: %1%, exec_timestamp: %2%")
					% joint.block->hash().to_string() % joint.block->hashables.exec_timestamp);
			}

			//cache late message
			if (joint.block->hashables.exec_timestamp < czr::seconds_since_epoch() + 600) //10 minutes
			{
				node.late_message_cache.add(item);
			}

			break;
		}
		case czr::validate_result_codes::invalid_block:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Invalid block: %1%, error message: %2%") % joint.block->hash().to_string() % result.err_msg);
			}

			//cache invalid block
			node.invalid_block_cache.add(joint.block->hash());
			break;
		}
		case czr::validate_result_codes::known_invalid_block:
		{
			if (node.config.logging.ledger_logging())
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Known invalid block: %1%") % joint.block->hash().to_string());
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

czr::node::node(czr::node_init & init_a, boost::asio::io_service & service_a, uint16_t peering_port_a, 
	boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::logging const & logging_a,
	czr::private_key const & node_key_a, dev::bytesConstRef restore_network_bytes_a) :
	node(init_a, service_a, application_path_a, alarm_a, czr::node_config(logging_a), node_key_a, restore_network_bytes_a)
{
}

czr::node::node(czr::node_init & init_a, boost::asio::io_service & service_a, 
	boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::node_config const & config_a, 
	czr::private_key const & node_key_a, dev::bytesConstRef restore_network_bytes_a) :
	io_service(service_a),
	config(config_a),
	alarm(alarm_a),
	capability(std::make_shared<czr::node_capability>(*this)),
	host(std::make_shared<p2p::host>(config.p2p, io_service, node_key_a, restore_network_bytes_a)),
	store(init_a.error, application_path_a / "data.ldb", config_a.lmdb_max_dbs),
	gap_cache(*this),
	ledger(store),
	key_manager(init_a.error, store.environment, application_path_a),
	wallet(init_a.error, *this),
	application_path(application_path_a),
	warmed_up(0),
	validation(std::make_shared<czr::validation>(*this)),
	chain(std::make_shared<czr::chain>(*this, [](std::shared_ptr<czr::block> block_a){})),
	block_processor(*this),
	block_processor_thread([this]() { this->block_processor.process_blocks(); })
{
	if (!init_a.error)
	{
		if (config.logging.node_lifetime_tracing())
		{
			BOOST_LOG(log) << "Constructing node";
		}
		
		czr::transaction transaction(store.environment, nullptr, true);
		try
		{
			czr::genesis::try_initialize(transaction, store);
		}
		catch (const std::exception & e)
		{
			BOOST_LOG(log) << boost::str(boost::format("Init genesis error: %1%") % e.what());
			transaction.abort();
			init_a.error = true;
		}
	}
}

czr::node::~node()
{
	stop();
}

bool czr::node::copy_with_compaction(boost::filesystem::path const & destination_file)
{
	return !mdb_env_copy2(store.environment.environment,
		destination_file.string().c_str(), MDB_CP_COMPACT);
}

void czr::node::process_local_joint(czr::joint_message const & joint)
{
	block_arrival.add(joint.block->hash());
	block_processor.add(czr::block_processor_item(joint, 0));
}

void czr::node::process_remote_joint(czr::joint_message const & joint, p2p::node_id const & remote_node_id)
{
	block_arrival.add(joint.block->hash());
	block_processor.add(czr::block_processor_item(joint, remote_node_id));
}

void czr::node::start()
{
	BOOST_LOG(log) << "Node starting, version: " << STR(CANONCHAIN_VERSION) << ".";

	host->register_capability(capability);
	host->start();

	ongoing_unhandle_flush();
	ongoing_retry_late_message();
}

void czr::node::stop()
{
	if (!is_stopped.test_and_set())
	{
		BOOST_LOG(log) << "Node stopping";

		host->stop();
		block_processor.stop();
		wallet.stop();
		if (block_processor_thread.joinable())
		{
			block_processor_thread.join();
		}
	}
}

//---ongoing_unhandle_flush
void czr::node::ongoing_unhandle_flush()
{
	std::weak_ptr<czr::node> node_w(shared_from_this());
	alarm.add(std::chrono::steady_clock::now() + std::chrono::minutes(1), [node_w]() {
		if (auto node_l = node_w.lock())
		{
			{
				czr::transaction transaction(node_l->store.environment, nullptr, true);
				std::chrono::seconds sec(-3600);
				auto dead_time = czr::future_from_epoch(sec);
				node_l->store.deadtime_unhandle_del(transaction, dead_time);
			}
			node_l->ongoing_unhandle_flush();
		}
	});


}

void czr::node::ongoing_retry_late_message()
{
	
	auto late_msg_info_list(late_message_cache.purge_list_ealier_than(czr::seconds_since_epoch()));
	for (auto info : late_msg_info_list)
		block_processor.add(info.item);

	std::weak_ptr<czr::node> node_w(shared_from_this());
	alarm.add(std::chrono::steady_clock::now() + std::chrono::seconds(5), [node_w]() {
		if (auto node_l = node_w.lock())
		{
			node_l->ongoing_retry_late_message();
		}
	});
}

dev::bytes czr::node::network_bytes()
{
	return host->network_bytes();
}

void czr::node::to_be_a_witness(std::shared_ptr<czr::witness> witness_a)
{
	m_witness = witness_a;
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
	for (unsigned i(0); i < service_threads_a; ++i)
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
				assert(false && "Unhandled io_service exception");
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
		("account_create", "Create new account")
		("account_remove", "Remove account")
		("account_import", "Imports account from json file")
		("account_list", "List all accounts")
		("vacuum", "Compact database. If data_path is missing, the database in data directory is compacted.")
		("snapshot", "Compact database and create snapshot, functions similar to vacuum but does not replace the existing database")
		("data_path", boost::program_options::value<std::string>(), "Use the supplied path as the data directory")
		("account", boost::program_options::value<std::string>(), "Defines <account> for other commands")
		("file", boost::program_options::value<std::string>(), "Defines <file> for other commands")
		("key", boost::program_options::value<std::string>(), "Defines the <key> for other commands, hex")
		("password", boost::program_options::value<std::string>(), "Defines <password> for other commands")
		("rpc_enable", "Rpc is become effective once")
		("rpc_enable_control", "Rpc_enable is become effective once")
		("witness","Start witness node");
	// clang-format on
}

//todo:find linux/mac/windows passwordget
/*
std::string czr::password_get(bool bconfirm)
{
	
	std::string hint_l("Please input your password");    
	hint_l += bconfirm ? " again:" : ":";
	std::cout << hint_l << std::endl;
	std::string password;
	char ch;
	while (ch = _getch())
	{
		if (ch == '\r' || ch == '\x3')//Enter or CTRL+C
			break;
		if (ch == '\b')  //BACK
		{
			password.pop_back();
		}
		password += ch;
		std::cout << "*";
	}
	std::cout << std::endl;
	return password;
}*/

bool czr::handle_node_options(boost::program_options::variables_map & vm)
{
	auto result(false);
	boost::filesystem::path data_path = vm.count("data_path") ? boost::filesystem::path(vm["data_path"].as<std::string>()) : czr::working_path();
	if (vm.count("account_create"))
	{
		//todo: get from input
		    std::string password = vm["password"].as<std::string>();
			inactive_node node(data_path);
			czr::transaction transaction(node.node->store.environment, nullptr, true);
			auto account(node.node->key_manager.create(transaction, password));
			std::cout << boost::str(boost::format("Account: %1%\n") % account.to_account());				
		
	}
	else if (vm.count("account_remove"))
	{
		if (vm.count("account") == 1)
		{
			//todo: get from input
			std::string password = vm["password"].as<std::string>();
			inactive_node node(data_path);
			czr::account account;
			if (!account.decode_account(vm["account"].as<std::string>()))
			{
				bool exists(node.node->key_manager.exists(account));
				if (exists)
				{
					czr::transaction transaction(node.node->store.environment, nullptr, true);
					auto error(node.node->key_manager.remove(transaction, account, password));
					if (error)
					{
						std::cerr << "Wrong password\n";
					}
				}
				else
				{
					std::cerr << "Account not found\n";
				}
			}
			else
			{
				std::cerr << "Invalid account\n";
			}
		}
		else
		{
			std::cerr << "Requires one <account> option\n";
		}
	}
	else if (vm.count("account_import"))
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

				inactive_node node(data_path);
				czr::transaction transaction(node.node->store.environment, nullptr, true);
				czr::key_content kc;
				bool error(node.node->key_manager.import(transaction, contents.str(), kc));
				if (!error)
				{
					std::cerr << "Import account " << kc.account.to_account() << std::endl;
					result = false;
				}
				else
				{
					std::cerr << "Unable to import account\n";
				}
			}
			else
			{
				std::cerr << "Unable to open <file>\n";
			}
		}
		else
		{
			std::cerr << "Requires one <file> option\n";
		}
	}
	else if (vm.count("account_list"))
	{
		inactive_node node(data_path);
		std::list<czr::account> account_list(node.node->key_manager.list());
		for (czr::account account : account_list)
		{
			std::cout << account.to_account() << '\n';
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
	node = std::make_shared<czr::node>(init, *service, 24000, path, alarm, logging, 0, dev::bytesConstRef());
}

czr::inactive_node::~inactive_node()
{
	node->stop();
}

czr::late_message_info::late_message_info(czr::block_processor_item const & item_a) :
	item(item_a),
	timestamp(item_a.joint.block->hashables.exec_timestamp),
	hash(item_a.joint.block->hash())
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

size_t czr::late_message_cache::size() const
{
	return container.size();
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

size_t czr::invalid_block_cache::size() const
{
	return container.size();
}
