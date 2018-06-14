#pragma once

#include <czr/p2p/common.hpp>
#include <czr/p2p/capability.hpp>

namespace czr
{
	class handshake_message
	{
	public:
		handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, uint256_union const & nonce_a);
		handshake_message(dev::RLP const & r);
		void stream_RLP(dev::RLPStream & s);

		uint16_t version;
		czr::czr_networks network;
		uint256_union nonce;
	};

	class ack_message
	{
	public:
		ack_message(czr::node_id const & node_id_a, czr::signature const & nonce_sig_a, std::list<czr::capability_desc> const & cap_descs_a);
		ack_message(dev::RLP const & r);
		void stream_RLP(dev::RLPStream & s);

		czr::node_id node_id;
		czr::signature nonce_sig;
		std::list<capability_desc> cap_descs;
	};
}