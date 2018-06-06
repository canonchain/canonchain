#include "peer.hpp"

czr::peer::peer(czr::host & host_a, std::shared_ptr<bi::tcp::socket> const & socket_a, czr::node_id const & node_id_a, std::shared_ptr<czr::frame_coder> const & frame_coder_a):
	host(host_a),
	socket(socket_a),
	my_node_id(node_id_a),
	frame_coder(frame_coder_a),
	is_drop(false)
{
}

void czr::peer::register_capability(std::shared_ptr<czr::peer_capability> const & cap)
{
	capabilities.push_back(cap);
}

void czr::peer::start()
{
	read_loop();
	ping_loop();
}

void czr::peer::read_loop()
{
	if (is_drop)
		return;

	auto this_l(shared_from_this());
	data.reserve(czr::message_header_size);
	ba::async_read(*socket, boost::asio::buffer(data, czr::message_header_size), [this, this_l](boost::system::error_code ec, std::size_t size)
	{
		if (!ec)
		{
			uint32_t body_size(this_l->frame_coder->deserialize_packet_size(data));
			if (body_size > czr::max_packet_size)
			{
				BOOST_LOG(this_l->host.node.log) << boost::str(boost::format("Too large body size %1%, max message body size %2%, node id") % body_size % czr::max_packet_size % my_node_id.to_string());
				drop();
				return;
			}
			data.reserve(body_size);
			ba::async_read(*socket, boost::asio::buffer(data, body_size), [this, this_l, body_size](boost::system::error_code ec, std::size_t size)
			{
				if (!ec)
				{
					dev::bytesConstRef packet(data.data(), body_size);
					if (!check_packet(packet))
					{
						BOOST_LOG(this_l->host.node.log) << boost::str(boost::format("invalid packet, size: %1%, data: %2%") % packet.size() % toHex(packet));
						disconnect(czr::disconnect_reason::bad_protocol);
						return;
					}
					else
					{
						auto packet_type = (czr::packet_type)dev::RLP(packet.cropped(0, 1)).toInt<unsigned>();
						dev::RLP r(packet.cropped(1));
						bool ok = read_packet(packet_type, r);
						if (!ok)
							BOOST_LOG(this_l->host.node.log) << "invalid rlp packet:" << dev::RLP(r);
					}
					read_loop();
				}
				else
				{
					BOOST_LOG(this_l->host.node.log) << "Error while peer reading data, message:" << ec.message();
					drop();
					return;
				}
			});
		}
		else
		{
			BOOST_LOG(this_l->host.node.log) << "Error while peer reading header, message:" << ec.message();
			drop();
		}
	});
}

bool czr::peer::check_packet(dev::bytesConstRef msg)
{
	if (msg[0] > 0x7f || msg.size() < 2)
		return false;
	if (dev::RLP(msg.cropped(1)).actualSize() + 1 != msg.size())
		return false;
	return true;
}

bool czr::peer::read_packet(czr::packet_type & type, dev::RLP const & r)
{
	try
	{
		//todo:
		return false;
	}
	catch (std::exception const & e)
	{
		BOOST_LOG(host.node.log) << boost::str(boost::format("Error while reading packet, packet type: %1% , rlp: %2%, message: %3%") % (unsigned)type % r %e.what());
		disconnect(czr::disconnect_reason::bad_protocol);
		return true;
	}
	return true;
}

void czr::peer::ping_loop()
{
	//todo:
}


bool czr::peer::is_connected()
{
	return socket->is_open();
}

void czr::peer::drop()
{
	is_drop = true;
	//todo:
}

void czr::peer::disconnect(czr::disconnect_reason const & reason)
{
	//todo:
}
