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
	namespace p2p
	{
		class host : public std::enable_shared_from_this<host>
		{
		public:
			host(p2p_config const & config_a, boost::asio::io_service & io_service_a, czr::private_key const & node_key, dev::bytesConstRef restore_network_bytes_a);
			void start();
			void stop();
			void register_capability(std::shared_ptr<icapability> cap);
			dev::bytes network_bytes() const;
			void on_node_table_event(node_id const & node_id_a, node_table_event_type const & type_a);
			std::unordered_map<node_id, bi::tcp::endpoint> peers() const;
			std::list<node_info> nodes() const;

		private:
			enum class peer_type
			{
				egress = 0,
				ingress = 1
			};

			void run();
			bool resolve_host(std::string const & addr, bi::tcp::endpoint & ep);
			void connect(std::shared_ptr<node_info> const & ne);
			size_t avaliable_peer_count(peer_type const & type);
			uint32_t max_peer_size(peer_type const & type);
			void keep_alive_peers();
			void try_connect_nodes(size_t const & avaliable_count);
			void start_listen(bi::address const & listen_ip, uint16_t const & port);
			void accept_loop();
			void do_handshake(std::shared_ptr<bi::tcp::socket> const & socket);
			void write_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer);
			void read_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, hash256 const & my_nonce);
			void write_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, handshake_message const & handshake, hash256 const & my_nonce);
			void read_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, hash256 const & my_nonce);
			void start_peer(std::shared_ptr<bi::tcp::socket> const & socket, ack_message const & ack);

			void restore_network(dev::bytesConstRef const & bytes);

			p2p_config const & config;
			boost::asio::io_service & io_service;
			czr::keypair alias;
			std::map<capability_desc, std::shared_ptr<icapability>> capabilities;

			std::unique_ptr<bi::tcp::acceptor> acceptor;
			std::unordered_map<node_id, std::weak_ptr<peer>> m_peers;
			mutable std::mutex m_peers_mutex;

			std::unordered_set<node_id> pending_conns;
			std::mutex pending_conns_mutex;

			std::shared_ptr<node_table> m_node_table;

			dev::bytes restore_network_bytes;

			std::atomic<bool> is_run;
			std::unique_ptr<boost::asio::deadline_timer> run_timer;
			const boost::posix_time::milliseconds run_interval = boost::posix_time::milliseconds(100);

			std::chrono::seconds const keep_alive_interval = std::chrono::seconds(30);
			std::chrono::steady_clock::time_point last_ping;

			std::chrono::seconds const try_connect_interval = std::chrono::seconds(3);
			std::chrono::steady_clock::time_point last_try_connect;
			std::chrono::seconds node_fallback_interval = std::chrono::seconds(20);

			std::chrono::steady_clock::time_point start_time;
			std::vector<std::shared_ptr<node_info>> bootstrap_nodes;

			boost::posix_time::milliseconds const handshake_timeout = boost::posix_time::milliseconds(5000);
		};

		class host_node_table_event_handler : public node_table_event_handler
		{
		public:
			host_node_table_event_handler(host & host_a)
				:host(host_a)
			{
			}

			virtual void process_event(node_id const & node_id_a, node_table_event_type const & type_a)
			{
				host.on_node_table_event(node_id_a, type_a);
			}

			host & host;
		};
	}
}