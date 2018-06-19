#pragma once

#include "czr/p2p/capability.hpp"
#include "czr/p2p/peer.hpp"
#include "czr/node/node.hpp"

namespace czr
{
	enum class sub_packet_type
	{
		joint = 0,

		packet_count = 0x10
	};

	class node_capability : public p2p::icapability
	{
	public:
		node_capability(czr::node & node_a);
		void on_connect(std::shared_ptr<p2p::peer> peer_a);
		void on_disconnect(std::shared_ptr<p2p::peer> peer_a);
		bool read_packet(std::shared_ptr<p2p::peer> peer_a, unsigned const & type, dev::RLP const & r);

	private:
		czr::node & node;
	};
}