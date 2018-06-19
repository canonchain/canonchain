#include "host.hpp"

#include<boost/algorithm/string.hpp>

using namespace czr::p2p;

host::host(p2p_config const & config_a, boost::asio::io_service & io_service_a,
	std::list<std::shared_ptr<icapability>> const & capabilities_a, 
	dev::bytesConstRef restore_network_bytes_a) :
	config(config_a),
	io_service(io_service_a),
	alias(network_alias(restore_network_bytes_a)),
	acceptor(std::make_unique<bi::tcp::acceptor>(io_service_a)),
	restore_network_bytes(restore_network_bytes_a.toBytes()),
	is_run(false),
	last_ping(std::chrono::steady_clock::time_point::min()),
	last_try_connect(std::chrono::steady_clock::time_point::min())
{
	for (auto & cap : capabilities_a)
	{
		capabilities.insert(std::make_pair(cap->desc, cap));
	}

	for (std::string const & bn : config.bootstrap_nodes)
	{
		if (!boost::istarts_with(bn, "czrnode://"))
		{
			BOOST_LOG_TRIVIAL(warning) << "Invald boostrap node: " << bn;
			continue;
		}

		std::string node_str(bn.substr(10));

		std::vector<std::string> node_id_and_addr;
		boost::split(node_id_and_addr, node_str, boost::is_any_of("@"));
		if (node_id_and_addr.size() != 2)
			BOOST_LOG_TRIVIAL(warning) << "Invald boostrap node :" << bn;
		node_id node_id;
		bool error(node_id.decode_hex(node_id_and_addr[0]));
		if (error)
		{
			BOOST_LOG_TRIVIAL(warning) << "Invald boostrap node :" << bn;
			continue;
		}

		std::string addr(node_id_and_addr[1]);
		bi::tcp::endpoint ep;
		error = resolve_host(addr, ep);
		if (error)
		{
			BOOST_LOG_TRIVIAL(warning) << "Invald boostrap node :" << bn;
			continue;
		}

		node_endpoint node_ep (ep.address(), ep.port(), ep.port());
		bootstrap_nodes.push_back(std::make_shared<node_info>(node_id, node_ep));
	}
}

void host::start()
{
	start_time = std::chrono::steady_clock::now();

	is_run = true;

	bi::address listen_ip;
	try
	{
		listen_ip = config.listen_ip.empty() ? bi::address_v4() : bi::address::from_string(config.listen_ip);
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(error) << "Invalid listen_ip:" << listen_ip << ", message:" << e.what();
		return;
	}

	uint16_t port(config.port);
	start_listen(listen_ip, port);
	accept_loop();

	m_node_table = std::make_shared<node_table>(io_service, alias, node_endpoint(listen_ip, port, port));
	m_node_table->set_event_handler(new host_node_table_event_handler(*this));
	m_node_table->start();

	for (auto & node : bootstrap_nodes)
		m_node_table->add_node(*node);

	restore_network(&restore_network_bytes);

	BOOST_LOG_TRIVIAL(info) << "P2P started, czrnode://" << alias.pub.to_string() << "@" << listen_ip << ":" << port;

	run_timer = std::make_unique<ba::deadline_timer>(io_service);
	run();
}

void host::stop()
{
	is_run = false;

	acceptor->cancel();
	if (acceptor->is_open())
		acceptor->close();

	run_timer->cancel();

	// disconnect peers
	for (unsigned n = 0;; n = 0)
	{
		std::lock_guard<std::mutex> lock(peers_mutex);
		for (auto i : peers)
			if (auto p = i.second.lock())
				if (p->is_connected())
				{
					p->disconnect(disconnect_reason::client_quit);
					n++;
				}
		if (!n)
			break;

		// poll so that peers send out disconnect packets
		io_service.poll();
	}

	//clear peers
	{
		std::lock_guard<std::mutex> lock(peers_mutex);
		peers.clear();
	}
}

void host::start_listen(bi::address const & listen_ip, uint16_t const & port)
{
	try
	{
		bi::tcp::endpoint endpoint(listen_ip, port);
		acceptor->open(endpoint.protocol());
		//acceptor->set_option(bi::tcp::acceptor::reuse_address(true));
		acceptor->bind(endpoint);
		acceptor->listen();

		BOOST_LOG_TRIVIAL(info) << boost::str(boost::format("P2P start listen on %1%:%2%") % listen_ip % port);
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(error) << boost::str(boost::format("Error while acceptor listen on %1%:%2%, message: %3%")
			% listen_ip % port % e.what());
		throw;
	}

}

void host::accept_loop()
{
	if (!is_run)
		return;

	auto socket(std::make_shared<bi::tcp::socket>(io_service));
	auto this_l(shared_from_this());
	acceptor->async_accept(*socket, [socket, this_l](boost::system::error_code const & ec) {

		BOOST_LOG_TRIVIAL(debug) << "Accept socket:" << socket->remote_endpoint();

		if (ec || !this_l->is_run)
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while accepting connections: %1%") % ec.message());
			try
			{
				if (socket->is_open())
					socket->close();
			}
			catch (...) {}
		}
		else
		{
			if (this_l->avaliable_peer_count(peer_type::ingress) == 0)
			{
				BOOST_LOG_TRIVIAL(info) << "Dropping socket due to too many peers, peer count: " << this_l->peers.size() 
					<< ",pending peers: " << this_l->pending_conns.size() << ",remote endpoint: " << socket->remote_endpoint() 
					<< ",max peers: " << this_l->max_peer_size(peer_type::ingress);
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

void host::run()
{
	if (!is_run)
		return;

	m_node_table->process_events();

	keep_alive_peers();

	size_t avaliable_count = avaliable_peer_count(peer_type::egress);
	if (avaliable_count > 0)
		try_connect_nodes(avaliable_count);

	run_timer->expires_from_now(run_interval);
	run_timer->async_wait([this](boost::system::error_code const & error)
	{
		run();
	});
}

bool host::resolve_host(std::string const & addr, bi::tcp::endpoint & ep)
{
	bool error(false);
	std::vector<std::string> split;
	boost::split(split, addr, boost::is_any_of(":"));
	unsigned port = czr::p2p::default_port;

	std::string host(split[0]);
	std::string port_str(split[1]);

	try
	{
		if (split.size() > 1)
			port = static_cast<uint16_t>(stoi(port_str));
	}
	catch (...) {}

	boost::system::error_code ec;
	bi::address address = bi::address::from_string(host, ec);
	if (!ec)
	{
		ep.address(address);
		ep.port(port);
	}
	else
	{
		boost::system::error_code ec;
		// resolve returns an iterator (host can resolve to multiple addresses)
		bi::tcp::resolver r(io_service);
		auto it = r.resolve(bi::tcp::resolver::query(host, std::to_string(port)), ec);
		if (ec)
		{
			BOOST_LOG_TRIVIAL(info) << "Error resolving host address... " << addr << " : " << ec.message();
			error = true;
		}
		else
			ep = *it;
	}
	return error;
}

void host::connect(std::shared_ptr<node_info> const & ne)
{
	if (!is_run)
		return;

	{
		std::lock_guard<std::mutex> lock(peers_mutex);
		if (peers.count(ne->id))
		{
			BOOST_LOG_TRIVIAL(debug) << "Aborted connect, node already connected, node id: " << ne->id.to_string();
			return;
		}
	}

	{
		std::lock_guard<std::mutex> lock(pending_conns_mutex);
		// prevent concurrently connecting to a node
		if (pending_conns.count(ne->id))
			return;
		pending_conns.insert(ne->id);
	}

	bi::tcp::endpoint ep(ne->endpoint);
	BOOST_LOG_TRIVIAL(debug) << "Attempting connection to node " << ne->id.to_string() << "@" << ep;
	std::shared_ptr<bi::tcp::socket> socket = std::make_shared<bi::tcp::socket>(io_service);
	auto this_l(shared_from_this());
	socket->async_connect(ep, [ne, ep, socket, this_l](boost::system::error_code const& ec)
	{
		if (ec)
		{
			BOOST_LOG_TRIVIAL(info) << "Connection refused to node " << ne->id.to_string() << "@" << ep << ", message: " << ec.message();
		}
		else
		{
			BOOST_LOG_TRIVIAL(info) << "Connecting to " << ne->id.to_string() << "@" << ep;
			this_l->do_handshake(socket);
		}

		{
			std::lock_guard<std::mutex> lock(this_l->pending_conns_mutex);
			this_l->pending_conns.erase(ne->id);
		}	
	});
}

size_t host::avaliable_peer_count(peer_type const & type)
{
	size_t count = peers.size() + pending_conns.size();
	if (max_peer_size(type) <= count)
		return 0;
	return max_peer_size(type) - peers.size() - pending_conns.size();
}

uint32_t host::max_peer_size(peer_type const & type)
{
	if (type == peer_type::egress)
		return config.max_peers / 2 + 1;
	else
		return config.max_peers;
}

void host::keep_alive_peers()
{
	if (std::chrono::steady_clock::now() - keep_alive_interval < last_ping)
		return;

	{
		std::lock_guard<std::mutex> lock(peers_mutex);
		for (auto it = peers.begin(); it != peers.end();)
			if (auto p = it->second.lock())
			{
				p->ping();
				++it;
			}
			else
				it = peers.erase(it);
	}

	last_ping = std::chrono::steady_clock::now();
}

void host::try_connect_nodes(size_t const & avaliable_count)
{
	if (std::chrono::steady_clock::now() - try_connect_interval < last_try_connect)
		return;

	//random find node in node table
	auto node_infos(m_node_table->get_random_nodes(avaliable_count));
	for (auto nf : node_infos)
	{
		connect(nf);
	}

	//connect to bootstrap nodes
	if (peers.size() == 0 && std::chrono::steady_clock::now() - start_time > node_fallback_interval)
	{
		for (auto bn : bootstrap_nodes)
		{
			if (!avaliable_peer_count(peer_type::egress))
				break;
			connect(bn);
		}
	}

	last_try_connect = std::chrono::steady_clock::now();
}

void host::do_handshake(std::shared_ptr<bi::tcp::socket> const & socket)
{
	if (!is_run)
		return;

	std::shared_ptr<ba::deadline_timer> idle_timer(std::make_shared<ba::deadline_timer>(socket->get_io_service()));
	idle_timer->expires_from_now(handshake_timeout);
	auto this_l(shared_from_this());
	idle_timer->async_wait([this_l, socket, idle_timer](boost::system::error_code const& ec)
	{
		if (!ec)
		{
			if (!socket->remote_endpoint().address().is_unspecified())
				BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Handshake timeout, remote endpoint: %1%") % socket->remote_endpoint());
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

void host::write_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer)
{
	if (!is_run)
		return;
	
	hash256 my_nonce;
	czr::random_pool.GenerateBlock(my_nonce.bytes.data(), my_nonce.bytes.size());
	handshake_message handshake(czr::p2p::version, czr::czr_network, my_nonce);

	std::shared_ptr<dev::bytes> write_buffer(std::make_shared<dev::bytes>());
	{
		dev::RLPStream s;
		s.append((unsigned)packet_type::handshake);
		handshake.stream_RLP(s);
		s.swapOut(*write_buffer);
	}

	frame_coder frame_coder;
	frame_coder.write_frame(write_buffer.get(), *write_buffer);

	auto this_l(shared_from_this());
	ba::async_write(*socket, ba::buffer(*write_buffer), [this_l, socket, idle_timer, my_nonce, write_buffer](const boost::system::error_code& ec, std::size_t bytes_transferred) {
		if (!ec)
		{
			this_l->read_handshake(socket, idle_timer, my_nonce);
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while sending handshake, message: %1%") % ec.message());
		}
	});
}

void host::read_handshake(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, hash256 const & my_nonce)
{
	if (!is_run)
		return;

	//read header
	std::shared_ptr<dev::bytes> header_buffer(std::make_shared<dev::bytes>(czr::p2p::tcp_header_size));
	auto this_l(shared_from_this());
	ba::async_read(*socket, ba::buffer(*header_buffer, czr::p2p::tcp_header_size), [this_l, header_buffer, socket, idle_timer, my_nonce](const boost::system::error_code& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			//read packet
			frame_coder frame_coder;
			uint32_t packet_size(frame_coder.deserialize_packet_size(*header_buffer));
			if (packet_size > czr::p2p::max_tcp_packet_size)
			{
				BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Too large packet size %1%, max message packet size %2%") % packet_size % czr::p2p::max_tcp_packet_size);
				return;
			}

			std::shared_ptr<dev::bytes> packet_buffer(std::make_shared<dev::bytes>(packet_size));
			ba::async_read(*socket, ba::buffer(*packet_buffer, packet_size), [this_l, packet_buffer, socket, idle_timer, my_nonce](const boost::system::error_code& ec, std::size_t bytes_transferred)
			{
				if (!ec)
				{
					dev::bytesConstRef packet(packet_buffer.get());
					packet_type type = (packet_type)dev::RLP(packet.cropped(0, 1)).toInt<unsigned>();
					if(type != packet_type::handshake)
					{
						BOOST_LOG_TRIVIAL(debug) <<boost::str(boost::format("Invalid shakehand packet type: %1%") % (unsigned)type);
						return;
					}

					try
					{
						dev::RLP r(packet.cropped(1));
						handshake_message handshake(r);
						if(handshake.network != czr::czr_network)
							return;

						this_l->write_ack(socket, idle_timer, handshake, my_nonce);
					}
					catch (std::exception const & e)
					{
						BOOST_LOG_TRIVIAL(debug) << "Error while starting peer, message: " << e.what();
					}
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Error while reading handshake data, message: %1%") % ec.message());
				}
			});
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while reading handshake header, message: %1%") % ec.message());
		}
	});
}

void host::write_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, handshake_message const & handshake, hash256 const & my_nonce)
{
	if (!is_run)
		return;

	std::list<capability_desc> cap_descs;
	for (auto const & pair : capabilities)
		cap_descs.push_back(pair.second->desc);

	czr::signature nonce_sig(czr::sign_message(alias.prv, alias.pub, handshake.nonce));
	ack_message ack(alias.pub, nonce_sig, cap_descs);

	std::shared_ptr<dev::bytes> write_buffer(std::make_shared<dev::bytes>());
	{
		dev::RLPStream s;
		s.append((unsigned)packet_type::ack);
		ack.stream_RLP(s);
		s.swapOut(*write_buffer);
	}

	frame_coder frame_coder;
	frame_coder.write_frame(write_buffer.get(), *write_buffer);

	auto this_l(shared_from_this());
	ba::async_write(*socket, ba::buffer(*write_buffer), [this_l, socket, idle_timer, my_nonce, write_buffer](const boost::system::error_code& ec, std::size_t bytes_transferred) {
		if (!ec)
		{
			this_l->read_ack(socket, idle_timer, my_nonce);
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while sending handshake, message: %1%") % ec.message());
		}
	});
}

void host::read_ack(std::shared_ptr<bi::tcp::socket> const & socket, std::shared_ptr<ba::deadline_timer> const & idle_timer, hash256 const & my_nonce)
{
	if (!is_run)
		return;

	//read header
	std::shared_ptr<dev::bytes> header_buffer(std::make_shared<dev::bytes>(czr::p2p::tcp_header_size));
	auto this_l(shared_from_this());
	ba::async_read(*socket, ba::buffer(*header_buffer, czr::p2p::tcp_header_size), [this_l, header_buffer, socket, idle_timer, my_nonce](const boost::system::error_code& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			//read packet
			frame_coder frame_coder;
			uint32_t packet_size(frame_coder.deserialize_packet_size(*header_buffer));
			if (packet_size > czr::p2p::max_tcp_packet_size)
			{
				BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Too large packet size %1%, max message packet size %2%") % packet_size % czr::p2p::max_tcp_packet_size);
				return;
			}

			std::shared_ptr<dev::bytes> packet_buffer(std::make_shared<dev::bytes>(packet_size));
			ba::async_read(*socket, ba::buffer(*packet_buffer, packet_size), [this_l, packet_buffer, socket, idle_timer, my_nonce](const boost::system::error_code& ec, std::size_t bytes_transferred)
			{
				idle_timer->cancel();

				if (!ec)
				{
					dev::bytesConstRef packet(packet_buffer.get());
					packet_type type = (packet_type)dev::RLP(packet.cropped(0, 1)).toInt<unsigned>();
					if (type != packet_type::ack)
					{
						BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Invalid shakehand packet type: %1%") % (unsigned)type);
						return;
					}

					try
					{
						dev::RLP r(packet.cropped(1));
						ack_message ack(r);
						bool is_bad_sig(czr::validate_message(ack.id, my_nonce, ack.nonce_sig));
						if (is_bad_sig)
						{
							BOOST_LOG_TRIVIAL(debug) << "Invalid nonce sig, node id: " << ack.id.to_string() << ", nonce: " << my_nonce.to_string() << ", sig:" << ack.nonce_sig.to_string();
							return;
						}

						this_l->start_peer(socket, ack);
					}
					catch (std::exception const & e)
					{
						BOOST_LOG_TRIVIAL(debug) << "Error while starting peer, message: " << e.what();
					}
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << boost::str(boost::format("Error while reading handshake data, message: %1%") % ec.message());
				}
			});
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while reading handshake header, message: %1%") % ec.message());
		}
	});
}

void host::start_peer(std::shared_ptr<bi::tcp::socket> const & socket, ack_message const & ack)
{
	if (!is_run)
		return;

	node_id remote_node_id(ack.id);
	try
	{
		std::shared_ptr<peer> new_peer(std::make_shared<peer>(socket, remote_node_id));
		//check self connect
		if (remote_node_id == alias.pub)
		{
			new_peer->disconnect(disconnect_reason::self_connect);
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
					BOOST_LOG_TRIVIAL(info) << boost::str(boost::format("Peer already exists, node id: %1%") % remote_node_id.to_string());
					new_peer->disconnect(disconnect_reason::duplicate_peer);
					return;
				}
			}

			//check max peers
			if(avaliable_peer_count(peer_type::ingress) == 0)
			{
				BOOST_LOG_TRIVIAL(info) << "Too many peers. peer count: " << peers.size() << ",pending peers: " << pending_conns.size() 
					<< ",remote node id: " << remote_node_id.to_string() << ",remote endpoint: " << socket->remote_endpoint() 
					<< ",max peers: " << max_peer_size(peer_type::ingress);

				new_peer->disconnect(disconnect_reason::too_many_peers);
				return;
			}

			//get peer capabilities
			unsigned offset = (unsigned)packet_type::user_packet;
			std::map<capability_desc, std::shared_ptr<peer_capability>> p_caps;
			for (auto const & pair : capabilities)
			{
				capability_desc const & desc(pair.first);
				if (std::find(ack.cap_descs.begin(), ack.cap_descs.end(), desc) != ack.cap_descs.end())
				{
					auto it(p_caps.find(desc));
					if (it != p_caps.end())
					{
						offset -= it->second->cap->packet_count();
					}

					auto const & cap(pair.second);
					p_caps[desc] = std::make_shared<peer_capability>(offset, cap);
					offset += cap->packet_count();
				}
			}
			if (p_caps.size() == 0)
			{
				new_peer->disconnect(disconnect_reason::useless_peer);
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
		BOOST_LOG_TRIVIAL(warning) << boost::str(boost::format("Error while starting Peer %1% : %2%, message: %3%")
			% remote_node_id.to_string() % socket->remote_endpoint() % e.what());
		try
		{
			if (socket->is_open())
				socket->close();
		}
		catch (...) {}
	}
}

void host::on_node_table_event(node_id const & node_id_a, node_table_event_type const & type_a)
{
	if (type_a == node_table_event_type::node_entry_added)
	{
		BOOST_LOG_TRIVIAL(info) << "Node entry added, id:" << node_id_a.to_string();

		if (std::shared_ptr<node_info> nf = m_node_table->get_node(node_id_a))
		{
			if(avaliable_peer_count(peer_type::egress) > 0)
				connect(nf);
		}
	}
	else if (type_a == node_table_event_type::node_entry_dropped)
	{
		BOOST_LOG_TRIVIAL(info) << "Node entry dropped, id:" << node_id_a.to_string();
	}
}

czr::keypair host::network_alias(dev::bytesConstRef const & bytes)
{
	dev::RLP r(bytes);
	if (r.itemCount() > 1)
		return czr::keypair((czr::private_key)r[1]);
	else
		return czr::keypair();
}

void host::restore_network(dev::bytesConstRef const & bytes)
{
	if (!bytes.size())
		return;

	dev::RLP r(bytes);
	unsigned version = r[0].toInt<unsigned>();
	if (r.itemCount() > 0 && r[0].isInt() && version >= czr::p2p::version)
	{
		// r[0] = version
		// r[1] = key
		// r[2] = nodes

		for (auto i : r[2])
		{
			// todo: ipv6
			if (i[0].itemCount() != 4 && i[0].size() != 4)
				continue;

			node_info n((node_id)i[3], node_endpoint(i));
			m_node_table->add_node(n);
		}
	}
}

dev::bytes host::save_network() const
{
	dev::RLPStream network;
	int count = 0;

	auto node_infos = m_node_table->snapshot();
	for (auto const & nf : node_infos)
	{
		network.appendList(4);
		nf->endpoint.stream_RLP(network, RLP_append::stream_inline);
		network << nf->id;
		count++;
	}
	// else: TODO: use previous configuration if available

	dev::RLPStream ret(3);
	ret << czr::p2p::version << alias.prv.data;
	ret.appendList(count);
	if (!!count)
		ret.appendRaw(network.out(), count);
	return ret.out();
}