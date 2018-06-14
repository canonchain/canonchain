#pragma once

#include <czr/p2p/common.hpp>
#include <czr/p2p/capability.hpp>

namespace czr
{
	namespace p2p
	{
		class handshake_message
		{
		public:
			handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, hash256 const & nonce_a);
			handshake_message(dev::RLP const & r);
			void stream_RLP(dev::RLPStream & s);

			uint16_t version;
			czr::czr_networks network;
			hash256 nonce;
		};

		class ack_message
		{
		public:
			ack_message(node_id const & node_id_a, czr::signature const & nonce_sig_a, std::list<capability_desc> const & cap_descs_a);
			ack_message(dev::RLP const & r);
			void stream_RLP(dev::RLPStream & s);

			node_id id;
			czr::signature nonce_sig;
			std::list<capability_desc> cap_descs;
		};
	}
}