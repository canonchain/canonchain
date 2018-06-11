#pragma once
#include <czr/p2p/common.hpp>
#include <czr/p2p/frame_coder.hpp>
#include <czr/p2p/peer.hpp>
#include <czr/p2p/node_discover.hpp>
#include <czr/node/node.hpp>

#include <unordered_map>

#include <boost/asio.hpp>

namespace bi = boost::asio::ip;
namespace ba = boost::asio;

namespace czr
{
	using node_id = uint256_union;

	class peer;
	class capability_desc;
	class icapability;
	class handshake_message;
	class frame_coder;
	class p2p_config;

	class host : std::enable_shared_from_this<czr::host>
	{
	public:
		host(czr::node & node_a, czr::p2p_config const & config_a, boost::asio::io_service & io_service_a,
			czr::node_id const & node_id_a, std::list<std::shared_ptr<czr::icapability>> const & capabilities_a);
		void start();
		void run();
		void start_listen();
		void accept_loop();
		void do_handshake(std::shared_ptr<bi::tcp::socket> const & socket);
		void write_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer);
		void read_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, std::shared_ptr<czr::frame_coder> const & frame_coder_a);
		void start_peer(std::shared_ptr<bi::tcp::socket> const & socket, czr::handshake_message const & handshake, std::shared_ptr<czr::frame_coder> const & frame_coder_a);
		void stop();

		czr::node & node;
		czr::p2p_config const & config;
		boost::asio::io_service & io_service;
		czr::node_id node_id;
		std::map<czr::capability_desc, std::shared_ptr<czr::icapability>> capabilities;

		std::unique_ptr<bi::tcp::acceptor> acceptor;
		std::unique_ptr<bi::tcp::resolver> resolver;
		std::unordered_map<czr::node_id, std::weak_ptr<czr::peer>> peers;
		std::mutex peers_mutex;

		std::shared_ptr<czr::node_discover> node_discover;
	};
}