#pragma once

#include <czr/p2p/common.hpp>
#include <czr/p2p/capability.hpp>
#include <czr/p2p/handshake.hpp>
#include <czr/p2p/node_table.hpp>
#include <czr/p2p/frame_coder.hpp>
#include <czr/p2p/peer.hpp>

#include <unordered_map>


namespace czr
{
	class host : std::enable_shared_from_this<czr::host>
	{
	public:
		host(czr::p2p_config const & config_a, boost::asio::io_service & io_service_a,
			std::list<std::shared_ptr<czr::icapability>> const & capabilities_a, 
			dev::bytesConstRef restore_network_bytes_a);
		void start();
		void stop();
		void on_node_table_event(czr::node_id const & node_id_a, czr::node_table_event_type const & type_a);

	private:
		std::chrono::seconds node_fallback_interval = std::chrono::seconds(20);

		enum class peer_type 
		{ 
			egress = 0, 
			ingress = 1
		};

		void run();
		bool resolve_host(std::string const & addr, bi::tcp::endpoint & ep);
		void connect(std::shared_ptr<czr::node_info> const & ne);
		size_t avaliable_peer_count(peer_type const & type);
		uint32_t max_peer_size(peer_type const & type);
		void keep_alive_peers();
		void start_listen(bi::address const & listen_ip, uint16_t const & port);
		void accept_loop();
		void do_handshake(std::shared_ptr<bi::tcp::socket> const & socket);
		void write_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer);
		void read_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, czr::uint256_union const & my_nonce);
		void write_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, czr::handshake_message const & handshake, czr::uint256_union const & my_nonce);
		void read_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, czr::uint256_union const & my_nonce);
		void start_peer(std::shared_ptr<bi::tcp::socket> const & socket, czr::ack_message const & ack);

		czr::keypair network_alias(dev::bytesConstRef const & bytes);
		void restore_network(dev::bytesConstRef const & bytes);
		dev::bytes save_network() const;

		czr::p2p_config const & config;
		boost::asio::io_service & io_service;
		czr::keypair const & alias;
		std::map<czr::capability_desc, std::shared_ptr<czr::icapability>> capabilities;

		std::unique_ptr<bi::tcp::acceptor> acceptor;
		std::unordered_map<czr::node_id, std::weak_ptr<czr::peer>> peers;
		std::mutex peers_mutex;

		std::unordered_set<czr::node_id> pending_conns;
		std::mutex pending_conns_mutex;

		std::shared_ptr<czr::node_table> node_table;

		dev::bytes restore_network_bytes;

		std::atomic<bool> is_run;
		std::unique_ptr<boost::asio::deadline_timer> run_timer;		
		const boost::posix_time::milliseconds run_interval = boost::posix_time::milliseconds(100);

		std::chrono::seconds const keep_alive_interval = std::chrono::seconds(30);
		std::chrono::steady_clock::time_point last_ping;

		std::chrono::steady_clock::time_point start_time;
		std::vector<std::shared_ptr<czr::node_info>> bootstrap_nodes;

		boost::posix_time::milliseconds const handshake_timeout = boost::posix_time::milliseconds(5000);
	};

	class host_node_table_event_handler : public czr::node_table_event_handler
	{
	public:
		host_node_table_event_handler(czr::host & host_a)
			:host(host_a)
		{
		}

		virtual void process_event(czr::node_id const & node_id_a, czr::node_table_event_type const & type_a)
		{
			host.on_node_table_event(node_id_a, type_a);
		}

		czr::host & host;
	};

}