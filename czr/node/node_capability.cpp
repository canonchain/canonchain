#include "node_capability.hpp"

#include <fstream>

czr::node_capability::node_capability(czr::node & node_a) 
	:icapability(p2p::capability_desc("czr", 0), (unsigned)czr::sub_packet_type::packet_count),
	node(node_a)
{
}

void czr::node_capability::on_connect(std::shared_ptr<p2p::peer> peer_a)
{
}

void czr::node_capability::on_disconnect(std::shared_ptr<p2p::peer> peer_a)
{
}

bool czr::node_capability::read_packet(std::shared_ptr<p2p::peer> peer_a, unsigned const & type, dev::RLP const & r)
{
	try
	{
		switch ((czr::sub_packet_type)type)
		{
		case czr::sub_packet_type::joint:
		{
			bool error;
			czr::joint message(error, r);
			if (error)
			{
				BOOST_LOG(node.log) << "Invalid new block message rlp: " << r;
				peer_a->disconnect(p2p::disconnect_reason::bad_protocol);
				return true;
			}

			if (node.config.logging.network_message_logging())
			{
				BOOST_LOG(node.log) << "Joint message, block hash: " << message.block->hash().to_string();
			}
			node.process_active(message);

			break;
		}
		default:
			return false;
		}
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(error) << "Peer error, node id: " << peer_a->remote_node_id().to_string()
			<< ", packet type: " << type << ", rlp: " << r << ", message: " << e.what();
		throw;
	}

	return true;
}
