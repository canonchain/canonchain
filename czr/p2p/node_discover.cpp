#include "node_discover.hpp"

#include<boost/log/trivial.hpp>

czr::node_discover::node_discover(boost::asio::io_service & io_service_a, czr::keypair const & alias_a, czr::node_endpoint const & endpoint):
	io_service(io_service_a),
	node_info(alias_a.pub, endpoint),
	secret(alias_a.prv.data),
	table(alias_a.pub),
	socket(std::make_unique<bi::udp::socket>(io_service_a)),
	endpoint((bi::udp::endpoint)endpoint)
{
}

czr::node_discover::~node_discover()
{
	socket->close();
}

void czr::node_discover::start()
{
	socket->open(bi::udp::v4());
	try
	{
		socket->bind(endpoint);
	}
	catch (...)
	{
		socket->bind(bi::udp::endpoint(bi::udp::v4(), endpoint.port()));
	}
	receive_loop();
	discover_loop();
}

void czr::node_discover::discover_loop()
{
	discover_timer = std::make_unique<ba::deadline_timer>(io_service);
	discover_timer->expires_from_now(discover_interval);
	auto this_l(shared_from_this());
	discover_timer->async_wait([this](boost::system::error_code const & ec)
	{
		if (ec.value() == boost::asio::error::operation_aborted)
			return;

		if (ec)
			BOOST_LOG_TRIVIAL(warning) << "Discover loop error: " << ec.value() << ":" << ec.message();

		BOOST_LOG_TRIVIAL(debug) << "Do discover";

		czr::node_id rand_node_id; //todo:gen randram node id;
		do_discover(rand_node_id);
	});
}

void czr::node_discover::do_discover(czr::node_id const & rand_node_id, unsigned const & round, std::shared_ptr<std::set<std::shared_ptr<czr::node_entry>>> tried_a)
{
	if (round == max_discover_rounds)
	{
		BOOST_LOG_TRIVIAL(debug) << "Terminating discover after " << round << " rounds.";
		discover_loop();
		return;
	}
	else if (!round && !tried_a)
		// initialized tried on first round
		tried_a = std::make_shared<std::set<std::shared_ptr<czr::node_entry>>>();

	std::vector<std::shared_ptr<czr::node_entry>> nearest = table.nearest_node_entries(rand_node_id);
	std::list<std::shared_ptr<czr::node_entry>> tried;
	for (unsigned i = 0; i < nearest.size() && tried.size() < s_alpha; i++)
		if (!tried_a->count(nearest[i]))
		{
			auto n = nearest[i];
			tried.push_back(n);

			//send find node
			czr::find_node_packet p(rand_node_id);

			//add find node timeout
			{
				std::lock_guard<std::mutex> lock(find_node_timeouts_mutex);
				find_node_timeouts.insert(std::make_pair(n->node_id, std::chrono::steady_clock::now()));
			}

			send((bi::udp::endpoint)n->endpoint, p);
		}

	if (tried.empty())
	{
		BOOST_LOG_TRIVIAL(debug) << "Terminating discover after " << round << " rounds.";
		discover_loop();
		return;
	}

	while (!tried.empty())
	{
		tried_a->insert(tried.front());
		tried.pop_front();
	}

	discover_timer = std::make_unique<ba::deadline_timer>(io_service);
	discover_timer->expires_from_now(boost::posix_time::milliseconds(req_timeout.count() * 2));
	discover_timer->async_wait([this, rand_node_id, round, tried_a](boost::system::error_code const& ec)
	{
		if (ec.value() == boost::asio::error::operation_aborted)
			return;

		if (ec)
			BOOST_LOG_TRIVIAL(debug) << "Do discover error: " << ec.value() << ":"<< ec.message();

		do_discover(rand_node_id, round + 1, tried_a);
	});
}

void czr::node_discover::receive_loop()
{
	auto this_l(shared_from_this());
	socket->async_receive_from(boost::asio::buffer(recv_buffer), recv_endpoint, [this, this_l](boost::system::error_code ec, size_t size)
	{
		if (ec)
			BOOST_LOG_TRIVIAL(warning) << "Receiving UDP message failed. " << ec.value() << " : " << ec.message();

		if (size > 0)
			handle_receive(recv_endpoint, dev::bytesConstRef(recv_buffer.data(), size));
		receive_loop();
	});
}

void czr::node_discover::handle_receive(bi::udp::endpoint const & from, dev::bytesConstRef const & data)
{
	try {
		std::unique_ptr<czr::discover_packet> packet = interpret_packet(from, data);
		if (!packet)
			return;

		if (packet->is_expired())
		{
			BOOST_LOG_TRIVIAL(debug) << "Invalid packet (timestamp in the past) from " << from.address().to_string() << ":" << from.port();
			return;
		}

		switch (packet->packet_type())
		{
		case  czr::discover_packet_type::ping:
		{
			auto in = dynamic_cast<czr::ping_packet const&>(*packet);
			czr::node_endpoint from_node_endpoint(from.address(), from.port(), in.tcp_port);
			table.add_node(czr::node_info(packet->node_id, from_node_endpoint));

			czr::pong_packet p(node_info.node_id);
			send(from, p);
			break;
		}
		case czr::discover_packet_type::pong:
		{
			auto in = dynamic_cast<czr::pong_packet const &>(*packet);
			// whenever a pong is received, check if it's in evictions
			bool found = false;
			czr::node_id evicted_node_id;
			eviction_entry eviction_entry;
			{
				std::lock_guard<std::mutex> lock(evictions_mutex);
				auto exists = evictions.find(packet->node_id);
				if (exists != evictions.end())
				{
					if (exists->second.evicted_time > std::chrono::steady_clock::now())
					{
						found = true;
						evicted_node_id = exists->first;
						eviction_entry = exists->second;
						evictions.erase(exists);
					}
				}
			}

			if (found)
			{
				if (auto n = table.get_node(eviction_entry.new_node_id))
					table.drop_node(n->node_id);
				if (auto n = table.get_node(evicted_node_id))
					n->pending = false;
			}
			else
			{
				// if not, check if it's known/pending or a pubk discovery ping
				if (auto n = table.get_node(packet->node_id))
					n->pending = false;
				else
				{
					{
						std::lock_guard<std::mutex> lock(pubk_discover_pings_mutex);

						if (!pubk_discover_pings.count(from.address()))
							return; // unsolicited pong; don't note node as active
						pubk_discover_pings.erase(from.address());
					}
					if (!table.have_node(packet->node_id))
						table.add_node(czr::node_info(packet->node_id, czr::node_endpoint(from.address(), from.port(), from.port())));
				}
			}

			BOOST_LOG_TRIVIAL(debug) << "PONG from "  << packet->node_id.to_string() << ":" << from;
			break;
		}
		case czr::discover_packet_type::find_node:
		{
			auto in = dynamic_cast<czr::find_node_packet const&>(*packet);
			std::vector<std::shared_ptr<czr::node_entry>> nearest = table.nearest_node_entries(in.target);
			static unsigned const nlimit = (czr::max_udp_packet_size - 129) / czr::neighbour::max_size;
			for (unsigned offset = 0; offset < nearest.size(); offset += nlimit)
			{
				czr::neighbours_packet p(node_info.node_id, nearest, offset, nlimit);
				send(from, p);
			}
			break;
		}
		case  czr::discover_packet_type::neighbours:
		{
			auto in = dynamic_cast<czr::neighbours_packet const&>(*packet);
			bool expected = false;
			auto now = std::chrono::steady_clock::now();
			{
				std::lock_guard<std::mutex> lock(find_node_timeouts_mutex);
				auto it(find_node_timeouts.find(in.node_id));
				if (it != find_node_timeouts.end())
				{
					if (now - it->second < req_timeout)
						expected = true;
					else
						find_node_timeouts.erase(it);
				}
			}
			if (!expected)
			{
				BOOST_LOG_TRIVIAL(debug) << "Dropping unsolicited neighbours packet from " << from.address();
				break;
			}

			for (auto n : in.neighbours)
				table.add_node(czr::node_info(n.node_id, n.endpoint));
			break;
		}
		}

		table.active_node(packet->node_id, from);
	}
	catch (std::exception const& _e)
	{
		BOOST_LOG_TRIVIAL(error) << "Exception processing message from " << from.address().to_string() << ":" << from.port() << ": " << _e.what();
	}
	catch (...)
	{
		BOOST_LOG_TRIVIAL(error) << "Exception processing message from " << from.address().to_string() << ":" << from.port();
	}
}

std::unique_ptr<czr::discover_packet> czr::node_discover::interpret_packet(bi::udp::endpoint const & from, dev::bytesConstRef data)
{
	std::unique_ptr<czr::discover_packet> packet;
	// hash + node id + sig + packet type + packet (smallest possible packet is empty neighbours packet which is 3 bytes)
	if (data.size() < sizeof(czr::hash256) + sizeof(czr::node_id) + sizeof(czr::signature) + 1 + 3)
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet (too small) from "	<< from.address().to_string() << ":" << from.port();
		return packet;
	}
	dev::bytesConstRef hash(data.cropped(0, sizeof(czr::hash256)));
	dev::bytesConstRef bytes_to_hash_cref(data.cropped(sizeof(czr::hash256), data.size() - sizeof(czr::hash256)));
	dev::bytesConstRef node_id_cref(bytes_to_hash_cref.cropped(0, sizeof(czr::node_id)));
	dev::bytesConstRef sig_cref(bytes_to_hash_cref.cropped(sizeof(czr::node_id), sizeof(czr::signature)));
	dev::bytesConstRef rlp_cref(bytes_to_hash_cref.cropped(sizeof(czr::node_id) + sizeof(czr::signature)));

	czr::hash256 echo(czr::blake2b_hash(bytes_to_hash_cref));
	dev::bytes echo_bytes(&echo.bytes[0], &echo.bytes[0] + echo.bytes.size());
	if (!hash.contentsEqual(echo_bytes))
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet (bad hash) from " << from.address().to_string() << ":" << from.port();
		return packet;
	}

	czr::node_id from_node_id;
	dev::bytesRef from_node_id_ref(from_node_id.bytes.data(), from_node_id.bytes.size());
	node_id_cref.copyTo(from_node_id_ref);

	czr::signature sig;
	dev::bytesRef sig_ref(sig.bytes.data(), sig.bytes.size());
	sig_cref.copyTo(sig_ref);

	bool sig_valid(czr::validate_message(from_node_id, czr::blake2b_hash(rlp_cref), sig));
	if (!sig_valid)
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet (bad signature) from " << from.address().to_string() << ":" << from.port();
		return packet;
	}

	try
	{
		dev::bytesConstRef packet_cref(rlp_cref.cropped(1));
		switch ((czr::discover_packet_type)rlp_cref[0])
		{
		case czr::discover_packet_type::ping:
		{
			packet = std::make_unique<czr::ping_packet>(from_node_id);
			break;
		}
		case  czr::discover_packet_type::pong:
		{
			packet = std::make_unique<czr::pong_packet>(from_node_id);
			break;
		}
		case czr::discover_packet_type::find_node:
		{
			packet = std::make_unique<czr::find_node_packet>(from_node_id);
			break;
		}
		case  czr::discover_packet_type::neighbours:
		{
			packet = std::make_unique<czr::neighbours_packet>(from_node_id);
			break;
		}
		default:
		{
			BOOST_LOG_TRIVIAL(debug) << "Invalid packet (unknown packet type) from " << from.address().to_string() << ":" << from.port();
			break;
		}
		}
		packet->interpret_RLP(packet_cref);
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet format " << from.address().to_string() << ":" << from.port() << " message:" <<e.what();
		return packet;
	}

	return packet;
}

void czr::node_discover::send(bi::udp::endpoint const & to_endpoint, czr::discover_packet const & packet)
{
	czr::send_udp_datagram datagram(to_endpoint);
	datagram.add_packet_and_sign(secret, packet);

	if (datagram.data.size() > czr::max_udp_packet_size)
		BOOST_LOG_TRIVIAL(debug) << "Sending truncated datagram, size: " << datagram.data.size() << ", packet type:" << (unsigned)packet.packet_type();

	std::lock_guard<std::mutex> lock(send_queue_mutex);
	send_queue.push_back(datagram);
	if (send_queue.size() == 1)
		do_write();
}

void czr::node_discover::do_write()
{
	const send_udp_datagram & datagram = send_queue[0];
	auto this_l(shared_from_this());
	bi::udp::endpoint endpoint(datagram.endpoint);
	socket->async_send_to(boost::asio::buffer(datagram.data), endpoint, [this, this_l, endpoint](boost::system::error_code ec, std::size_t size)
	{
		if (ec)
			BOOST_LOG_TRIVIAL(warning) << "Sending UDP message failed. " << ec.value() << " : " << ec.message();

		{
			std::lock_guard<std::mutex> lock(send_queue_mutex);
			send_queue.pop_front();
			if (send_queue.empty())
				return;
		}
		do_write();
	});
}