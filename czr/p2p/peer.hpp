#pragma once
#include <czr/p2p/common.hpp>
#include <czr/p2p/frame_coder.hpp>
#include <czr/p2p/host.hpp>
#include <czr/lib/numbers.hpp>
#include <czr/rlp/Common.h>
#include <czr/rlp/RLP.h>

#include <boost/asio.hpp>

namespace ba = boost::asio;
namespace bi = boost::asio::ip;

namespace czr
{
	using node_id = uint256_union;

	enum class disconnect_reason
	{
		disconnect_requested = 0,
		tcp_error = 1,
		bad_protocol = 2,
		useless_peer = 3,
		too_many_peers = 4,
		duplicate_peer = 5,
		self_connect = 6,
		client_quit = 7,
		too_large_packet_size = 8,
		no_disconnect = 0xffff,
	};

	std::string reason_of(czr::disconnect_reason reason)
	{
		switch (reason)
		{
		case czr::disconnect_reason::disconnect_requested: return "Disconnect was requested.";
		case czr::disconnect_reason::tcp_error: return "Low-level TCP communication error.";
		case czr::disconnect_reason::bad_protocol: return "Data format error.";
		case czr::disconnect_reason::useless_peer: return "Peer had no use for this node.";
		case czr::disconnect_reason::too_many_peers: return "Peer had too many connections.";
		case czr::disconnect_reason::duplicate_peer: return "Peer was already connected.";
		case czr::disconnect_reason::client_quit: return "Peer is exiting.";
		case czr::disconnect_reason::self_connect: return "Connected to ourselves.";
		case czr::disconnect_reason::too_large_packet_size: return "Too large packet size.";
		case czr::disconnect_reason::no_disconnect: return "(No disconnect has happened.)";
		default: return "Unknown reason.";
		}
	}

	class host;
	class capability_desc;
	class peer_capability;
	enum class packet_type;

	class peer : std::enable_shared_from_this<czr::peer>
	{
	public:
		peer(czr::host & host_a, std::shared_ptr<bi::tcp::socket> const & socket_a, czr::node_id const & node_id_a, std::shared_ptr<czr::frame_coder> const & frame_coder_a);
		void register_capability(std::shared_ptr<czr::peer_capability> const & cap);
		void start();
		void ping();
		dev::RLPStream & prep(dev::RLPStream & s, czr::packet_type const & type, unsigned const & size = 0);
		void send(dev::RLPStream & s);
		bool is_connected();
		void disconnect(czr::disconnect_reason const & reason);

	private:
		void read_loop();
		bool check_packet(dev::bytesConstRef msg);
		bool read_packet(unsigned const & type, dev::RLP const & r);
		void do_write();
		void drop(czr::disconnect_reason const & reason);

		czr::host & host;
		std::shared_ptr<bi::tcp::socket> socket;
		czr::node_id my_node_id;
		std::list<std::shared_ptr<czr::peer_capability>> capabilities;
		std::shared_ptr<czr::frame_coder> frame_coder;
		dev::bytes read_buffer;
		std::deque<dev::bytes> write_queue;
		std::mutex write_queue_mutex;

		bool is_dropped;
	};
}