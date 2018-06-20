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


	class peer_info
	{
	public:
		peer_info()
		{
		}

		peer_info(std::shared_ptr<p2p::peer> peer_a):
			peer(peer_a)
		{
		}
		
		std::shared_ptr<p2p::peer> try_lock_peer() const
		{
			return peer.lock();
		}

		bool is_known_block(czr::block_hash const & block_hash_a) const 
		{
			return known_blocks.count(block_hash_a);
		}

		void mark_as_known_block(czr::block_hash const & block_hash_a)
		{
			known_blocks.insert(block_hash_a);
		}

		std::weak_ptr<p2p::peer> peer;

	private:
		std::unordered_set<czr::block_hash> known_blocks;
	};

	class node_capability : public p2p::icapability
	{
	public:
		node_capability(czr::node & node_a);
		void on_connect(std::shared_ptr<p2p::peer> peer_a);
		void on_disconnect(std::shared_ptr<p2p::peer> peer_a);
		bool read_packet(std::shared_ptr<p2p::peer> peer_a, unsigned const & type, dev::RLP const & r);
		void send_block(czr::joint_message const & message);
		void mark_as_known_block(p2p::node_id node_id_a, czr::block_hash block_hash_a);
	private:
		czr::node & node;
		std::unordered_map<p2p::node_id, czr::peer_info> peers;
		std::mutex peers_mutex;
	};
}