#include "peer.hpp"

czr::peer::peer(std::shared_ptr<bi::tcp::socket> const & socket_a, czr::node_id const & node_id_a):
	socket(socket_a),
	node_id(node_id_a),
	is_dropped(false),
	frame_coder(std::make_shared<czr::frame_coder>())
{
	_last_received = std::chrono::steady_clock::now();
}

czr::peer::~peer()
{
	try {
		if (socket->is_open())
			socket->close();
	}
	catch (...) {}
}

void czr::peer::register_capability(std::shared_ptr<czr::peer_capability> const & cap)
{
	capabilities.push_back(cap);
}

void czr::peer::start()
{
	ping();
	read_loop();
}

bool czr::peer::is_connected()
{
	return socket->is_open();
}

void czr::peer::disconnect(czr::disconnect_reason const & reason)
{
	BOOST_LOG_TRIVIAL(info) << "Disconnecting (our reason: " << czr::reason_of(reason) << ")";

	if (socket->is_open())
	{
		dev::RLPStream s;
		prep(s, czr::packet_type::disconect, 1) << (unsigned)reason;
		send(s);
	}
	drop(reason);
}

std::chrono::steady_clock::time_point czr::peer::last_received()
{
	return _last_received;
}

void czr::peer::ping()
{
	dev::RLPStream s;
	send(prep(s, czr::packet_type::ping));
}

void czr::peer::read_loop()
{
	if (is_dropped)
		return;

	auto this_l(shared_from_this());
	read_buffer.reserve(czr::tcp_header_size);
	ba::async_read(*socket, boost::asio::buffer(read_buffer, czr::tcp_header_size), [this, this_l](boost::system::error_code ec, std::size_t size)
	{
		if (!ec)
		{
			uint32_t packet_size(this_l->frame_coder->deserialize_packet_size(read_buffer));
			if (packet_size > czr::max_tcp_packet_size)
			{
				BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Too large body size %1%, max message body size %2%") % packet_size % czr::max_tcp_packet_size);
				drop(czr::disconnect_reason::too_large_packet_size);
				return;
			}
			read_buffer.reserve(packet_size);
			ba::async_read(*socket, boost::asio::buffer(read_buffer, packet_size), [this, this_l, packet_size](boost::system::error_code ec, std::size_t size)
			{
				if (!ec)
				{
					dev::bytesConstRef packet(read_buffer.data(), packet_size);
					if (!check_packet(packet))
					{
						BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("invalid packet, size: %1%, packet: %2%") % packet.size() % toHex(packet));
						disconnect(czr::disconnect_reason::bad_protocol);
						return;
					}
					else
					{
						auto packet_type = dev::RLP(packet.cropped(0, 1)).toInt<unsigned>();
						dev::RLP r(packet.cropped(1));
						bool ok = read_packet(packet_type, r);
						if (!ok)
							BOOST_LOG_TRIVIAL(debug) << "invalid rlp packet:" << dev::RLP(r);
					}
					read_loop();
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "Error while peer reading data, message:" << ec.message();
					drop(czr::disconnect_reason::tcp_error);
					return;
				}
			});
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "Error while peer reading header, message:" << ec.message();
			drop(czr::disconnect_reason::tcp_error);
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

bool czr::peer::read_packet(unsigned const & type, dev::RLP const & r)
{
	_last_received = std::chrono::steady_clock::now();

	try
	{
		if (type < (unsigned)czr::packet_type::user_packet)
		{
			switch ((czr::packet_type)type)
			{
			case czr::packet_type::ping:
			{
				dev::RLPStream s;
				send(prep(s, czr::packet_type::pong));
				break;
			}
			case czr::packet_type::pong:
			{
				break;
			}
			case czr::packet_type::disconect:
			{
				auto reason = (czr::disconnect_reason)r[0].toInt<unsigned>();
				if (!r[0].isInt())
					drop(czr::disconnect_reason::bad_protocol);
				else
				{
					std::string reason_str = czr::reason_of(reason);
					BOOST_LOG_TRIVIAL(info) << "Disconnect (reason: " << reason_str << ")";
					drop(czr::disconnect_reason::disconnect_requested);
				}
				break;
			}
			default:
				return false;
			}

			return true;
		}

		auto this_l(shared_from_this());
		for (auto & p_cap : capabilities)
		{
			if (type >= p_cap->offset && type < p_cap->cap->packet_count())
				return p_cap->cap->read_packet(this_l, type - p_cap->offset, r);
		}

		return false;
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while reading packet, packet type: %1% , rlp: %2%, message: %3%") % (unsigned)type % r %e.what());
		disconnect(czr::disconnect_reason::bad_protocol);
		return true;
	}
	return true;
}

dev::RLPStream & czr::peer::prep(dev::RLPStream & s, czr::packet_type const & type, unsigned const & size)
{
	return s.append((unsigned)type).appendList(size);
}

void czr::peer::send(dev::RLPStream & s)
{
	dev::bytes b;
	s.swapOut(b);
	dev::bytesConstRef packet(&b);
	if (!check_packet(packet))
	{
		BOOST_LOG_TRIVIAL(warning) << "Invalid send packet:" << dev::toHex(packet);
	}

	if (!socket->is_open())
		return;

	bool doWrite = false;
	{
		std::lock_guard<std::mutex> lock(write_queue_mutex);
		write_queue.push_back(std::move(b));
		doWrite = (write_queue.size() == 1);
	}

	if (doWrite)
		do_write();
}

void czr::peer::do_write()
{
	dev::bytes const* out = nullptr;
	{
		std::lock_guard<std::mutex> lock(write_queue_mutex);
		frame_coder->write_frame(&write_queue[0], write_queue[0]);
		out = &write_queue[0];
	}
	auto this_l(shared_from_this());
	ba::async_write(*socket, ba::buffer(*out),
		[this, this_l](boost::system::error_code ec, std::size_t size) {

		if (ec)
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error sending: %1%")% ec.message());
			drop(czr::disconnect_reason::tcp_error);
			return;
		}

		{
			std::lock_guard<std::mutex> lock(write_queue_mutex);
			write_queue.pop_front();
			if (write_queue.empty())
				return;
		}
		do_write();
	});
}

void czr::peer::drop(czr::disconnect_reason const & reason)
{
	if (is_dropped)
		return;
	if (socket->is_open())
	try
	{
		boost::system::error_code ec;
		BOOST_LOG_TRIVIAL(info) << "Closing " << socket->remote_endpoint(ec) << " (" << reason_of(reason) << ")";
		socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
		socket->close();
	}
	catch (...) {}

	is_dropped = true;
}
