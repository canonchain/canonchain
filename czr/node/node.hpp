#pragma once

#include <czr/lib/utility.hpp>

#include <czr/node/validation.hpp>
#include <czr/node/chain.hpp>
#include <czr/ledger.hpp>
#include <czr/node/wallet.hpp>
#include <czr/p2p/host.hpp>
#include <czr/node/node_capability.hpp>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>

#include <boost/asio.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/log/trivial.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/log/sources/logger.hpp>

namespace boost
{
	namespace program_options
	{
		class options_description;
		class variables_map;
	}
}

namespace czr
{
	class node;
	class operation
	{
	public:
		bool operator> (czr::operation const &) const;
		std::chrono::steady_clock::time_point wakeup;
		std::function<void()> function;
	};
	class alarm
	{
	public:
		alarm(boost::asio::io_service &);
		~alarm();
		void add(std::chrono::steady_clock::time_point const &, std::function<void()> const &);
		void run();
		boost::asio::io_service & service;
		std::mutex mutex;
		std::condition_variable condition;
		std::priority_queue<operation, std::vector<operation>, std::greater<operation>> operations;
		std::thread thread;
	};

	class gap_information
	{
	public:
		std::chrono::steady_clock::time_point arrival;
		czr::block_hash hash;
	};

	class gap_cache
	{
	public:
		gap_cache(czr::node &);
		void add(MDB_txn *, std::shared_ptr<czr::block>);
		void purge_old();
		boost::multi_index_container<
			czr::gap_information,
			boost::multi_index::indexed_by<
			boost::multi_index::ordered_non_unique<boost::multi_index::member<gap_information, std::chrono::steady_clock::time_point, &gap_information::arrival>>,
			boost::multi_index::hashed_unique<boost::multi_index::member<gap_information, czr::block_hash, &gap_information::hash>>>>
			blocks;
		size_t const max = 256;
		std::mutex mutex;
		czr::node & node;
	};

	class block_arrival_info
	{
	public:
		std::chrono::steady_clock::time_point arrival;
		czr::block_hash hash;
	};
	// This class tracks blocks that are probably live because they arrived in a UDP packet
	// This gives a fairly reliable way to differentiate between blocks being inserted via bootstrap or new, live blocks.
	class block_arrival
	{
	public:
		void add(czr::block_hash const &);
		bool recent(czr::block_hash const &);
		boost::multi_index_container<
			czr::block_arrival_info,
			boost::multi_index::indexed_by<
			boost::multi_index::ordered_non_unique<boost::multi_index::member<czr::block_arrival_info, std::chrono::steady_clock::time_point, &czr::block_arrival_info::arrival>>,
			boost::multi_index::hashed_unique<boost::multi_index::member<czr::block_arrival_info, czr::block_hash, &czr::block_arrival_info::hash>>>>
			arrival;
		std::mutex mutex;
	};

	class logging
	{
	public:
		logging();
		void serialize_json(boost::property_tree::ptree &) const;
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		bool upgrade_json(unsigned, boost::property_tree::ptree &);
		bool ledger_logging() const;
		bool ledger_duplicate_logging() const;
		bool network_logging() const;
		bool network_message_logging() const;
		bool network_packet_logging() const;
		bool network_keepalive_logging() const;
		bool node_lifetime_tracing() const;
		bool log_rpc() const;
		bool callback_logging() const;
		bool log_to_cerr() const;
		void init(boost::filesystem::path const &);

		bool ledger_logging_value;
		bool ledger_duplicate_logging_value;
		bool network_logging_value;
		bool network_message_logging_value;
		bool network_packet_logging_value;
		bool network_keepalive_logging_value;
		bool node_lifetime_tracing_value;
		bool log_rpc_value;
		bool log_to_cerr_value;
		bool flush;
		uintmax_t max_size;
		uintmax_t rotation_size;
		boost::log::sources::logger_mt log;
	};

	class node_init
	{
	public:
		node_init();
		bool error;
	};

	class node_config
	{
	public:
		node_config();
		node_config(czr::logging const &);
		void serialize_json(boost::property_tree::ptree &) const;
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		czr::logging logging;
		p2p::p2p_config p2p;
		unsigned password_fanout;
		unsigned io_threads;
		std::string callback_address;
		uint16_t callback_port;
		std::string callback_target;
		int lmdb_max_dbs;
	};

	class node_observers
	{
	public:
		czr::observer_set<std::shared_ptr<czr::block>, czr::validate_result const &> blocks;
		czr::observer_set<bool> wallet;
		czr::observer_set<czr::account const &, bool> account_balance;
		czr::observer_set<czr::endpoint const &> endpoint;
		czr::observer_set<> disconnect;
		czr::observer_set<> started;
	};

	class block_processor_item
	{
	public:
		block_processor_item(czr::joint);
		czr::joint joint;
	};
	// Processing blocks is a potentially long IO operation
	// This class isolates block insertion from other operations like servicing network operations
	class block_processor
	{
	public:
		block_processor(czr::node &);
		~block_processor();
		void stop();
		void flush();
		void add(czr::block_processor_item const &);
		void process_receive_many(czr::block_processor_item const &);
		void process_receive_many(std::deque<czr::block_processor_item> &);
		czr::validate_result process_receive_one(MDB_txn *, czr::joint const &);
		void process_blocks();
		czr::node & node;

	private:
		bool stopped;
		bool idle;
		std::deque<czr::block_processor_item> blocks;
		std::mutex mutex;
		std::condition_variable condition;
	};

	class late_message_info
	{
	public:
		late_message_info(czr::joint const & message_a);
		uint64_t timestamp;
		czr::block_hash hash;
		czr::joint const & message;
	};

	class late_message_cache
	{
	public:
		late_message_cache(size_t const & capacity_a = 100000);

		void add(czr::late_message_info const & info);
		std::vector<czr::late_message_info> purge_list_ealier_than(uint64_t const & timestamp);

	private:
		boost::multi_index_container<
			czr::late_message_info,
			boost::multi_index::indexed_by<
			boost::multi_index::hashed_unique<boost::multi_index::member<late_message_info, czr::block_hash, &late_message_info::hash>>,
			boost::multi_index::ordered_non_unique<boost::multi_index::member<late_message_info, uint64_t, &late_message_info::timestamp>>>>
			container;
		size_t capacity;
	};

	class invalid_block_cache
	{
	public:
		invalid_block_cache(size_t const & capacity_a = 1000);

		void add(czr::block_hash const & hash_a);
		bool contains(czr::block_hash const & hash_a);

	private:
		boost::multi_index_container<
			czr::block_hash,
			boost::multi_index::indexed_by<
			boost::multi_index::sequenced<>,
			boost::multi_index::hashed_unique<boost::multi_index::identity<czr::block_hash>>>>
			container;
		size_t capacity;
	};

	class chain;
	class validation;

	class node : public std::enable_shared_from_this<czr::node>
	{
	public:
		node(czr::node_init & init_a, boost::asio::io_service & service_a, uint16_t peering_port_a, boost::filesystem::path const & application_path_a, 
			czr::alarm & alarm_a, czr::logging const & logging_a, dev::bytesConstRef restore_network_bytes);
		node(czr::node_init & init_a, boost::asio::io_service & service_a, boost::filesystem::path const & application_path_a, 
			czr::alarm & alarm_a, czr::node_config const & config_a, dev::bytesConstRef restore_network_bytes);
		~node();
		template <typename T>
		void background(T action_a)
		{
			alarm.service.post(action_a);
		}
		bool copy_with_compaction(boost::filesystem::path const &);
		void start();
		void stop();
		std::shared_ptr<czr::node> shared();
		int store_version();
		void process_active(czr::joint const &);
		czr::block_hash latest(czr::account const &);
		czr::uint128_t balance(czr::account const &);
		std::unique_ptr<czr::block> block(czr::block_hash const &);
		void ongoing_store_flush();
		void ongoing_retry_late_message();
		void backup_wallet();
		dev::bytes network_bytes();

		boost::asio::io_service & io_service;
		czr::node_config config;
		czr::alarm & alarm;
		boost::log::sources::logger_mt log;
		std::shared_ptr<p2p::host> host;
		czr::block_store store;
		czr::gap_cache gap_cache;
		czr::ledger ledger;
		boost::filesystem::path application_path;
		czr::node_observers observers;
		czr::wallets wallets;
		unsigned warmed_up;
		std::shared_ptr<czr::validation> validation;
		std::shared_ptr<czr::chain> chain;
		czr::block_processor block_processor;
		std::thread block_processor_thread;
		czr::block_arrival block_arrival;
		czr::late_message_cache late_message_cache;
		czr::invalid_block_cache invalid_block_cache;
		static std::chrono::minutes constexpr backup_interval = std::chrono::minutes(5);
	};

	class thread_runner
	{
	public:
		thread_runner(boost::asio::io_service &, unsigned);
		~thread_runner();
		void join();
		std::vector<std::thread> threads;
	};

	void add_node_options(boost::program_options::options_description &);
	bool handle_node_options(boost::program_options::variables_map &);

	class inactive_node
	{
	public:
		inactive_node(boost::filesystem::path const & path = czr::working_path());
		~inactive_node();
		boost::filesystem::path path;
		boost::shared_ptr<boost::asio::io_service> service;
		czr::alarm alarm;
		czr::logging logging;
		czr::node_init init;
		std::shared_ptr<czr::node> node;
	};
}
