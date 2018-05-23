#pragma once

//#include <czr/config.hpp>
//#include <czr/lib/numbers.hpp>
#include <czr/lib/utility.hpp>

#include <czr/node/consensus.hpp>
#include <czr/ledger.hpp>
#include <czr/node/wallet.hpp>

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
		czr::uint128_t bootstrap_threshold(MDB_txn *);
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
	class peer_information
	{
	public:
		peer_information(czr::endpoint const &, unsigned);
		peer_information(czr::endpoint const &, std::chrono::steady_clock::time_point const &, std::chrono::steady_clock::time_point const &);
		czr::endpoint endpoint;
		std::chrono::steady_clock::time_point last_contact;
		std::chrono::steady_clock::time_point last_attempt;
		std::chrono::steady_clock::time_point last_bootstrap_attempt;
		unsigned network_version;
	};
	class peer_attempt
	{
	public:
		czr::endpoint endpoint;
		std::chrono::steady_clock::time_point last_attempt;
	};
	class peer_container
	{
	public:
		peer_container(czr::endpoint const &);
		// We were contacted by endpoint, update peers
		void contacted(czr::endpoint const &, unsigned);
		// Unassigned, reserved, self
		bool not_a_peer(czr::endpoint const &);
		// Returns true if peer was already known
		bool known_peer(czr::endpoint const &);
		// Notify of peer we received from
		bool insert(czr::endpoint const &, unsigned);
		std::unordered_set<czr::endpoint> random_set(size_t);
		void random_fill(std::array<czr::endpoint, 8> &);
		// List of all peers
		std::vector<czr::endpoint> list();
		std::map<czr::endpoint, unsigned> list_version();
		// A list of random peers with size the square root of total peer count
		std::vector<czr::endpoint> list_sqrt();
		// Get the next peer for attempting bootstrap
		czr::endpoint bootstrap_peer();
		// Purge any peer where last_contact < time_point and return what was left
		std::vector<czr::peer_information> purge_list(std::chrono::steady_clock::time_point const &);
		// Should we reach out to this endpoint with a keepalive message
		bool reachout(czr::endpoint const &);
		size_t size();
		size_t size_sqrt();
		bool empty();
		std::mutex mutex;
		czr::endpoint self;
		boost::multi_index_container<
			peer_information,
			boost::multi_index::indexed_by<
			boost::multi_index::hashed_unique<boost::multi_index::member<peer_information, czr::endpoint, &peer_information::endpoint>>,
			boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_contact>>,
			boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_attempt>, std::greater<std::chrono::steady_clock::time_point>>,
			boost::multi_index::random_access<>,
			boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_bootstrap_attempt>>>>
			peers;
		boost::multi_index_container<
			peer_attempt,
			boost::multi_index::indexed_by<
			boost::multi_index::hashed_unique<boost::multi_index::member<peer_attempt, czr::endpoint, &peer_attempt::endpoint>>,
			boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_attempt, std::chrono::steady_clock::time_point, &peer_attempt::last_attempt>>>>
			attempts;
		// Called when a new peer is observed
		std::function<void(czr::endpoint const &)> peer_observer;
		std::function<void()> disconnect_observer;
	};
	class send_info
	{
	public:
		uint8_t const * data;
		size_t size;
		czr::endpoint endpoint;
		std::function<void(boost::system::error_code const &, size_t)> callback;
	};
	class message_statistics
	{
	public:
		message_statistics();
		std::atomic<uint64_t> keepalive;
		std::atomic<uint64_t> publish;
		std::atomic<uint64_t> confirm_req;
		std::atomic<uint64_t> confirm_ack;
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
	class network
	{
	public:
		network(czr::node &, uint16_t);
		void receive();
		void stop();
		void receive_action(boost::system::error_code const &, size_t);
		void publish(MDB_txn * transaction, czr::publish & message);
		void merge_peers(std::array<czr::endpoint, 8> const &);
		void send_keepalive(czr::endpoint const &);
		void send_buffer(uint8_t const *, size_t, czr::endpoint const &, std::function<void(boost::system::error_code const &, size_t)>);
		czr::endpoint endpoint();
		czr::endpoint remote;
		std::array<uint8_t, 512> buffer;
		boost::asio::ip::udp::socket socket;
		std::mutex socket_mutex;
		boost::asio::ip::udp::resolver resolver;
		czr::node & node;
		uint64_t bad_sender_count;
		bool on;
		uint64_t error_count;
		czr::message_statistics incoming;
		czr::message_statistics outgoing;
		static uint16_t const node_port = czr::czr_network == czr::czr_networks::czr_live_network ? 7075 : 54000;
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
		bool network_publish_logging() const;
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
		bool network_publish_logging_value;
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
		node_config(uint16_t, czr::logging const &);
		void serialize_json(boost::property_tree::ptree &) const;
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		uint16_t peering_port;
		czr::logging logging;
		std::vector<std::string> preconfigured_peers;
		unsigned bootstrap_fraction_numerator;
		unsigned password_fanout;
		unsigned io_threads;
		bool enable_voting;
		unsigned bootstrap_connections;
		unsigned bootstrap_connections_max;
		std::string callback_address;
		uint16_t callback_port;
		std::string callback_target;
		int lmdb_max_dbs;
		static std::chrono::seconds constexpr keepalive_period = std::chrono::seconds(60);
		static std::chrono::seconds constexpr keepalive_cutoff = keepalive_period * 5;
		static std::chrono::minutes constexpr wallet_backup_interval = std::chrono::minutes(5);
	};
	class node_observers
	{
	public:
		czr::observer_set<std::shared_ptr<czr::block>, czr::process_return const &> blocks;
		czr::observer_set<bool> wallet;
		czr::observer_set<czr::account const &, bool> account_balance;
		czr::observer_set<czr::endpoint const &> endpoint;
		czr::observer_set<> disconnect;
		czr::observer_set<> started;
	};

	class block_processor_item
	{
	public:
		block_processor_item(czr::publish);
		czr::publish publish;
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
		czr::process_return process_receive_one(MDB_txn *, czr::publish const &);
		void process_blocks();
		czr::node & node;

	private:
		bool stopped;
		bool idle;
		std::deque<czr::block_processor_item> blocks;
		std::mutex mutex;
		std::condition_variable condition;
	};
	class node : public std::enable_shared_from_this<czr::node>
	{
	public:
		node(czr::node_init & init_a, boost::asio::io_service & service_a, uint16_t peering_port_a, boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::logging const & logging_a);
		node(czr::node_init & init_a, boost::asio::io_service & service_a, boost::filesystem::path const & application_path_a, czr::alarm & alarm_a, czr::node_config const & config_a);
		~node();
		template <typename T>
		void background(T action_a)
		{
			alarm.service.post(action_a);
		}
		void send_keepalive(czr::endpoint const &);
		bool copy_with_compaction(boost::filesystem::path const &);
		void keepalive(std::string const &, uint16_t);
		void start();
		void stop();
		std::shared_ptr<czr::node> shared();
		int store_version();
		void process_active(czr::publish const &);
		void keepalive_preconfigured(std::vector<std::string> const &);
		czr::block_hash latest(czr::account const &);
		czr::uint128_t balance(czr::account const &);
		std::unique_ptr<czr::block> block(czr::block_hash const &);
		void ongoing_keepalive();
		void ongoing_store_flush();
		void backup_wallet();
		void add_initial_peers();
		boost::asio::io_service & service;
		czr::node_config config;
		czr::alarm & alarm;
		boost::log::sources::logger_mt log;
		czr::block_store store;
		czr::gap_cache gap_cache;
		czr::ledger ledger;
		czr::network network;
		czr::peer_container peers;
		boost::filesystem::path application_path;
		czr::node_observers observers;
		czr::wallets wallets;
		unsigned warmed_up;
		czr::block_processor block_processor;
		std::thread block_processor_thread;
		czr::block_arrival block_arrival;
		static std::chrono::seconds constexpr period = std::chrono::seconds(60);
		static std::chrono::seconds constexpr cutoff = period * 5;
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
