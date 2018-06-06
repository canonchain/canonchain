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
		duplicate_peer = 1,
		too_many_peers = 2,
		bad_protocol = 3,
		self_connect = 4,
		useless_peer = 5,
	};

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
		void read_loop();
		bool check_packet(dev::bytesConstRef msg);
		bool read_packet(czr::packet_type & type, dev::RLP const & r);
		void ping_loop();
		bool is_connected();
		void drop();
		void disconnect(czr::disconnect_reason const & reason);

		czr::host & host;
		std::shared_ptr<bi::tcp::socket> socket;
		czr::node_id my_node_id;
		std::list<std::shared_ptr<czr::peer_capability>> capabilities;
		std::shared_ptr<czr::frame_coder> frame_coder;

	private:
		std::vector<uint8_t> data;
		bool is_drop;
	};
}