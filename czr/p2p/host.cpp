#include "host.hpp"

czr::host::host(czr::node & node_a, czr::p2p_config const & config_a, boost::asio::io_service & io_service_a,
	czr::node_id const & node_id_a, std::list<std::shared_ptr<czr::icapability>> const & capabilities_a) :
	node(node_a),
	config(config_a),
	io_service(io_service_a),
	node_id(node_id_a),
	acceptor(std::make_unique<bi::tcp::acceptor>(io_service_a)),
	resolver(std::make_unique<bi::tcp::resolver>(io_service_a))
{
	for (auto & cap : capabilities_a)
	{
		capabilities.insert(std::make_pair(cap->desc, cap));
	}
}

void czr::host::start()
{
	start_listen();
	accept_loop();
}

void czr::host::start_listen()
{
	//todo: support ipv6

	bi::tcp::endpoint endpoint;
	try
	{
		bi::tcp::resolver::query query(bi::tcp::v4(), config.host.empty() ? bi::address_v4::any().to_string() : config.host, 
			std::to_string(config.port));
		endpoint = *resolver->resolve(query);	
	}
	catch (std::exception const & e)
	{
		BOOST_LOG(node.log) << boost::str(boost::format("Error while resolve %1%:%2%, message: %3%")
			% config.host % config.port % e.what());
		throw;
	}

	try
	{
		acceptor->open(endpoint.protocol());
		acceptor->set_option(bi::tcp::acceptor::reuse_address(true));
		acceptor->bind(endpoint);
		acceptor->listen();
	}
	catch (std::exception const & e)
	{
		BOOST_LOG(node.log) << boost::str(boost::format("Error while acceptor listen on %1%:%2%, message: %3%")
			% (config.host.empty() ? endpoint.address().to_string() : config.host) % endpoint.port() % e.what());
		throw;
	}
}

void czr::host::accept_loop()
{
	auto socket(std::make_shared<bi::tcp::socket>(io_service));
	auto this_l(shared_from_this());
	acceptor->async_accept(*socket, [socket, this_l](boost::system::error_code const & ec) {
		if (ec)
		{
			BOOST_LOG(this_l->node.log) << boost::str(boost::format("Error while accepting connections: %1%") % ec.message());
		}
		else
		{
			if (this_l->peers.size() > this_l->config.max_peers)
			{
				BOOST_LOG(this_l->node.log) << boost::str(boost::format("Dropping socket due to maximum peer count %1%, current peer count %2%, remote endpoint: %3%") % this_l->config.max_peers % this_l->peers.size() % socket->remote_endpoint());
				try
				{
					if (socket->is_open())
						socket->close();
				}
				catch (...) {}
			}

			this_l->do_handshake(socket);

			this_l->accept_loop();
		}
	});
}

void czr::host::do_handshake(std::shared_ptr<bi::tcp::socket> const & socket)
{
	std::shared_ptr<ba::deadline_timer> idle_timer(std::make_shared<ba::deadline_timer>(socket->get_io_service()));
	idle_timer->expires_from_now(handshake_timeout);
	auto this_l(shared_from_this());
	idle_timer->async_wait([this_l, socket, idle_timer](boost::system::error_code const& _ec)
	{
		if (!_ec)
		{
			if (!socket->remote_endpoint().address().is_unspecified())
				BOOST_LOG(this_l->node.log) << boost::str(boost::format("Handshake timeout, remote endpoint: %1%") % socket->remote_endpoint());
			try
			{
				if (socket->is_open())
					socket->close();
				idle_timer->cancel();
			}
			catch (...) {}
		}
	});

	write_handshake(socket, idle_timer);
}

void czr::host::write_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer)
{
	std::list<capability_desc> cap_descs;
	for (auto const & pair : capabilities)
		cap_descs.push_back(pair.second->desc);
	czr::handshake_message handshake(czr::p2p_version, czr::czr_network, node_id, cap_descs);

	dev::RLPStream s;
	s.append((unsigned)czr::packet_type::handshake);
	handshake.stream_RLP(s);

	dev::bytes write_buffer;
	s.swapOut(write_buffer);

	std::shared_ptr<czr::frame_coder> frame_coder(std::make_shared<czr::frame_coder>());
	frame_coder->write_frame(&write_buffer, write_buffer);

	auto this_l(shared_from_this());
	ba::async_write(*socket, ba::buffer(write_buffer), [this_l, socket, idle_timer, frame_coder](const boost::system::error_code& ec, std::size_t bytes_transferred) {
		if (!ec)
		{
			this_l->read_handshake(socket, idle_timer, frame_coder);
		}
		else
		{
			BOOST_LOG(this_l->node.log) << boost::str(boost::format("Error while sending handshake, message: %1%") % ec.message());
		}
	});
}

void czr::host::read_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, std::shared_ptr<czr::frame_coder> const & frame_coder_a)
{
	//read header
	dev::bytes header_buffer;
	auto this_l(shared_from_this());
	ba::async_read(*socket, ba::buffer(header_buffer, czr::message_header_size), [this_l, header_buffer, socket, idle_timer, frame_coder_a](const boost::system::error_code& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			//read packet
			uint32_t packet_size(frame_coder_a->deserialize_packet_size(header_buffer));
			if (packet_size > czr::max_packet_size)
			{
				BOOST_LOG(this_l->node.log) << boost::str(boost::format("Too large packet size %1%, max message packet size %2%") % packet_size % czr::max_packet_size);
				return;
			}

			std::shared_ptr<dev::bytes> packet_buffer(std::make_shared<dev::bytes>());
			ba::async_read(*socket, ba::buffer(*packet_buffer, packet_size), [this_l, packet_buffer, socket, idle_timer, frame_coder_a](const boost::system::error_code& ec, std::size_t bytes_transferred)
			{
				idle_timer->cancel();

				if (!ec)
				{
					dev::bytesConstRef packet(packet_buffer.get());
					czr::packet_type packet_type = (czr::packet_type)dev::RLP(packet.cropped(0, 1)).toInt<unsigned>();
					if(packet_type != czr::packet_type::handshake)
					{
						BOOST_LOG(this_l->node.log) <<boost::str(boost::format("Invalid shakehand packet type: %1%") % (unsigned)packet_type);
						return;
					}

					try
					{
						dev::RLP r(packet.cropped(1));
						czr::handshake_message handshake(r);
						this_l->start_peer(socket, handshake, frame_coder_a);
					}
					catch (std::exception const & e)
					{
						BOOST_LOG(this_l->node.log) << "Error while starting peer, message: " << e.what();
					}
				}
				else
				{
					BOOST_LOG(this_l->node.log) << boost::str(boost::format("Error while reading handshake data, message: %1%") % ec.message());
				}
			});
		}
		else
		{
			BOOST_LOG(this_l->node.log) << boost::str(boost::format("Error while reading handshake header, message: %1%") % ec.message());
		}
	});
}

void czr::host::start_peer(std::shared_ptr<bi::tcp::socket> const & socket, czr::handshake_message const & handshake, std::shared_ptr<czr::frame_coder> const & frame_coder_a)
{
	czr::node_id remote_node_id(handshake.node_id);
	try
	{
		std::shared_ptr<czr::peer> new_peer(std::make_shared<czr::peer>(*this, socket, remote_node_id, frame_coder_a));
		//check self connect
		if (remote_node_id == node_id)
		{
			new_peer->disconnect(czr::disconnect_reason::self_connect);
			return;
		}

		{
			std::lock_guard<std::mutex> lock(peers_mutex);

			//check duplicate
			if (peers.count(remote_node_id) && !!peers[remote_node_id].lock())
			{
				auto exist_peer(peers[remote_node_id].lock());
				if (exist_peer->is_connected())
				{
					BOOST_LOG(node.log) << boost::str(boost::format("Peer already exists, node id: %1%") % remote_node_id.to_string());
					new_peer->disconnect(czr::disconnect_reason::duplicate_peer);
					return;
				}
			}

			//check max peers
			if(peers.size() >= config.max_peers)
			{
				BOOST_LOG(node.log) << boost::str(boost::format("Too many peer, maximum peer count %1%, current peer count %2%, node id: %3%") % config.max_peers % peers.size() % remote_node_id.to_string());
				new_peer->disconnect(czr::disconnect_reason::too_many_peers);
				return;
			}

			//get peer capabilities
			unsigned offset = (unsigned)czr::packet_type::user_packet;
			std::map<capability_desc, std::shared_ptr<peer_capability>> p_caps;
			for (auto const & pair : capabilities)
			{
				capability_desc const & desc(pair.first);
				if (std::find(handshake.cap_descs.begin(), handshake.cap_descs.end(), desc) != handshake.cap_descs.end())
				{
					auto it(p_caps.find(desc));
					if (it != p_caps.end())
					{
						offset -= it->second->cap->packet_count();
					}

					auto const & cap(pair.second);
					p_caps[desc] = std::make_shared<czr::peer_capability>(desc, offset, cap);
					offset += cap->packet_count();
				}
			}
			if (p_caps.size() == 0)
			{
				new_peer->disconnect(czr::disconnect_reason::useless_peer);
				return;
			}

			for (auto const & p_cap : p_caps)
				new_peer->register_capability(p_cap.second);

			new_peer->start();

			peers[remote_node_id] = new_peer;
		}
	}
	catch (std::exception const & e)
	{
		BOOST_LOG(node.log) << boost::str(boost::format("Error while starting Peer %1% : %2%, message: %3%") 
			% remote_node_id.to_string() % socket->remote_endpoint() % e.what());
		try
		{
			if (socket->is_open())
				socket->close();
		}
		catch (...) {}
	}
}

void czr::host::stop()
{
}

