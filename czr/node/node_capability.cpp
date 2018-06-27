#include "node_capability.hpp"

#include <fstream>

czr::node_capability::node_capability(czr::node & node_a) 
	:icapability(p2p::capability_desc("czr", 0), (unsigned)czr::sub_packet_type::packet_count),
	node(node_a)
{
}

void czr::node_capability::on_connect(std::shared_ptr<p2p::peer> peer_a)
{
	std::lock_guard<std::mutex> lock(peers_mutex);
	peers[peer_a->remote_node_id()] = czr::peer_info(peer_a);
}

void czr::node_capability::on_disconnect(std::shared_ptr<p2p::peer> peer_a)
{
	std::lock_guard<std::mutex> lock(peers_mutex);
	peers.erase(peer_a->remote_node_id());
}

bool czr::node_capability::read_packet(std::shared_ptr<p2p::peer> peer_a, unsigned const & type, dev::RLP const & r)
{
	if (node.config.logging.network_packet_logging())
	{
		BOOST_LOG(node.log) << "node id: " << peer_a->remote_node_id().to_string() << ", packet type: " << type << ", rlp: " << r;
	}

	try
	{
		switch ((czr::sub_packet_type)type)
		{
		case czr::sub_packet_type::joint:
		{
			bool error;
			czr::joint_message message(error, r);
			if (error)
			{
				if (node.config.logging.network_logging())
				{
					BOOST_LOG(node.log) << "Invalid new block message rlp: " << r;
				}
				peer_a->disconnect(p2p::disconnect_reason::bad_protocol);
				return true;
			}

			czr::block_hash block_hash(message.block->hash());
			if (node.config.logging.network_message_logging())
			{
				BOOST_LOG(node.log) << "Joint message, block hash: " << block_hash.to_string();
			}

			node.process_active(message);

			mark_as_known_block(peer_a->remote_node_id(), block_hash);

			break;
		}
		default:
			return false;
		}
	}
	catch (std::exception const & e)
	{
		if (node.config.logging.network_logging())
		{
			BOOST_LOG_TRIVIAL(error) << "Peer error, node id: " << peer_a->remote_node_id().to_string()
				<< ", packet type: " << type << ", rlp: " << r << ", message: " << e.what();
		}
		throw;
	}

	return true;
}

void czr::node_capability::send_block(czr::joint_message const & message)
{
	czr::block_hash block_hash(message.block->hash());
	std::lock_guard<std::mutex> lock(peers_mutex);
	for (auto it = peers.begin(); it != peers.end();)
	{
		czr::peer_info pi(it->second);
		if (auto p = pi.try_lock_peer())
		{
			it++;
			if (pi.is_known_block(block_hash))
				continue;

			dev::RLPStream s;
			message.stream_RLP(s);
			p->send(s);
		}
		else
			it = peers.erase(it);
	}
}

void czr::node_capability::mark_as_known_block(p2p::node_id node_id_a, czr::block_hash block_hash_a)
{
	std::lock_guard<std::mutex> lock(peers_mutex);
	peers[node_id_a].mark_as_known_block(block_hash_a);
}

