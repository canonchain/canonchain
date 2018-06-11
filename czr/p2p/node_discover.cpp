#include "node_discover.hpp"

#include<boost/log/trivial.hpp>

czr::node_discover::node_discover(boost::asio::io_service & io_service_a, czr::keypair const & alias_a, czr::node_endpoint const & endpoint):
	io_service(io_service_a),
	node_info(alias_a.pub, endpoint),
	secret(alias_a.prv.data),
	socket(std::make_unique<bi::udp::socket>(io_service_a)),
	endpoint((bi::udp::endpoint)endpoint)
{
	for (unsigned i = 0; i < s_bins; i++)
		states[i].distance = i;
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
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(error) << "Node discovery start fail: " << e.what();
	}
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

	std::vector<std::shared_ptr<czr::node_entry>> nearest = nearest_node_entries(rand_node_id);
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
			add_node(czr::node_info(packet->node_id, from_node_endpoint));

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
				if (auto n = get_node(eviction_entry.new_node_id))
					drop_node(n);
				if (auto n = get_node(evicted_node_id))
					n->pending = false;
			}
			else
			{
				// if not, check if it's known/pending or a pubk discovery ping
				if (auto n = get_node(packet->node_id))
					n->pending = false;
				else
					add_node(czr::node_info(packet->node_id, czr::node_endpoint(from.address(), from.port(), from.port())));
			}

			BOOST_LOG_TRIVIAL(debug) << "PONG from "  << packet->node_id.to_string() << ":" << from;
			break;
		}
		case czr::discover_packet_type::find_node:
		{
			auto in = dynamic_cast<czr::find_node_packet const&>(*packet);
			std::vector<std::shared_ptr<czr::node_entry>> nearest = nearest_node_entries(in.target);
			static unsigned const nlimit = (max_udp_packet_size - 129) / czr::neighbour::max_size;
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
				add_node(czr::node_info(n.node_id, n.endpoint));
			break;
		}
		}

		note_active_node(packet->node_id, from);
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
	std::unique_ptr<czr::discover_packet> packet = std::unique_ptr<czr::discover_packet>();
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

	if (datagram.data.size() > max_udp_packet_size)
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

void czr::node_discover::ping(czr::node_endpoint const & to)
{
	czr::node_endpoint src;
	czr::ping_packet p(node_info.node_id);
	send(to, p);
}

std::shared_ptr<czr::node_entry> czr::node_discover::get_node(czr::node_id node_id_a)
{
	std::lock_guard<std::mutex> lock(nodes_mutex);
	return nodes.count(node_id_a) ? nodes[node_id_a] : std::shared_ptr<czr::node_entry>();
}

std::vector<std::shared_ptr<czr::node_entry>> czr::node_discover::nearest_node_entries(czr::node_id const & target_a)
{
	// send s_alpha FindNode packets to nodes we know, closest to target
	static unsigned last_bin = s_bins - 1;
	unsigned head = czr::node_entry::calc_distance(node_info.node_id, target_a);
	unsigned tail = head == 0 ? last_bin : (head - 1) % s_bins;

	std::map<unsigned, std::list<std::shared_ptr<czr::node_entry>>> found;

	// if d is 0, then we roll look forward, if last, we reverse, else, spread from d
	if (head > 1 && tail != last_bin)
		while (head != tail && head < s_bins)
		{
			std::lock_guard<std::mutex> lock(states_mutex);
			for (auto const & n : states[head].nodes)
				if (auto p = n.lock())
					found[czr::node_entry::calc_distance(target_a, p->node_id)].push_back(p);

			if (tail)
				for (auto const & n : states[tail].nodes)
					if (auto p = n.lock())
						found[czr::node_entry::calc_distance(target_a, p->node_id)].push_back(p);

			head++;
			if (tail)
				tail--;
		}
	else if (head < 2)
		while (head < s_bins)
		{
			std::lock_guard<std::mutex> lock(states_mutex);
			for (auto const & n : states[head].nodes)
				if (auto p = n.lock())
					found[czr::node_entry::calc_distance(target_a, p->node_id)].push_back(p);
			head++;
		}
	else
		while (tail > 0)
		{
			std::lock_guard<std::mutex> lock(states_mutex);
			for (auto const& n : states[tail].nodes)
				if (auto p = n.lock())
					found[czr::node_entry::calc_distance(target_a, p->node_id)].push_back(p);
			tail--;
		}

	std::vector<std::shared_ptr<czr::node_entry>> ret;
	for (auto& nodes : found)
		for (auto const& n : nodes.second)
			if (ret.size() < s_bucket_size && !!n->endpoint)
				ret.push_back(n);
	return ret;
}

std::shared_ptr<czr::node_entry> czr::node_discover::add_node(czr::node_info const & node_a, czr::node_relation relation_a)
{
	if (relation_a == czr::node_relation::known)
	{
		auto ret = std::make_shared<czr::node_entry>(node_info.node_id, node_a.node_id, node_a.endpoint);
		ret->pending = false;
		{
			std::lock_guard<std::mutex> lock(nodes_mutex);
			nodes[node_a.node_id] = ret;
		}
		note_active_node(node_a.node_id, node_a.endpoint);
		return ret;
	}

	if (!node_a.endpoint)
		return std::shared_ptr<czr::node_entry>();

	{
		std::lock_guard<std::mutex> lock(nodes_mutex);
		if (nodes.count(node_a.node_id))
			return nodes[node_a.node_id];
	}

	auto ret = std::make_shared<czr::node_entry>(node_info.node_id, node_a.node_id, node_a.endpoint);
	{
		std::lock_guard<std::mutex> lock(nodes_mutex);
		nodes[node_a.node_id] = ret;
	}

	BOOST_LOG_TRIVIAL(debug) << "addNode pending for " << node_a.endpoint;

	ping(node_a.endpoint);

	return ret;
}

void czr::node_discover::drop_node(std::shared_ptr<czr::node_entry> node_a)
{
	{
		std::lock_guard<std::mutex> lock(states_mutex);
		czr::node_bucket & s = bucket_UNSAFE(node_a.get());
		s.nodes.remove_if([node_a](std::weak_ptr<czr::node_entry> const & bucket_entry)
		{
			return bucket_entry.lock() == node_a;
		});
	}

	{
		std::lock_guard<std::mutex> lock(nodes_mutex);
		nodes.erase(node_a->node_id);
	}

	// notify host
	BOOST_LOG_TRIVIAL(debug) << "p2p.nodes.drop " << node_a->node_id.to_string();
	if (node_event_handler)
		node_event_handler->append_event(node_a->node_id, czr::node_discover_event_type::node_entry_dropped);
}

czr::node_bucket & czr::node_discover::bucket_UNSAFE(czr::node_entry const * node_a)
{
	return states[node_a->distance - 1];
}

void czr::node_discover::note_active_node(czr::node_id const & node_id_a, bi::udp::endpoint const& endpoint_a)
{
	//self
	if (node_id_a == node_info.node_id)
		return;

	std::shared_ptr<czr::node_entry> new_node = get_node(node_id_a);
	if (new_node && !new_node->pending)
	{
		BOOST_LOG_TRIVIAL(debug) << "Noting active node: " << node_id_a.to_string() << " " << endpoint_a.address().to_string()	<< ":" << endpoint.port();
		new_node->endpoint.address = endpoint_a.address();
		new_node->endpoint.udp_port = endpoint_a.port();

		std::shared_ptr<czr::node_entry> node_to_evict;
		{
			std::lock_guard<std::mutex> lock(states_mutex);
			// Find a bucket to put a node to
			czr::node_bucket & s = bucket_UNSAFE(new_node.get());
			auto & bucket_nodes = s.nodes;

			// check if the node is already in the bucket
			auto it = bucket_nodes.begin();
			for (; it != bucket_nodes.end() ; it++)
			{
				if (it->lock() == new_node)
					break;
			}

			if (it != bucket_nodes.end())
			{
				// if it was in the bucket, move it to the last position
				bucket_nodes.splice(bucket_nodes.end(), bucket_nodes, it);
			}
			else
			{
				if (bucket_nodes.size() < czr::s_bucket_size)
				{
					// if it was not there, just add it as a most recently seen node
					// (i.e. to the end of the list)
					bucket_nodes.push_back(new_node);
					if (node_event_handler)
						node_event_handler->append_event(new_node->node_id, czr::node_discover_event_type::node_entry_added);
				}
				else
				{
					// if bucket is full, start eviction process for the least recently seen node
					node_to_evict = bucket_nodes.front().lock();
					// It could have been replaced in addNode(), then weak_ptr is expired.
					// If so, just add a new one instead of expired
					if (!node_to_evict)
					{
						bucket_nodes.pop_front();
						bucket_nodes.push_back(new_node);
						if (node_event_handler)
							node_event_handler->append_event(new_node->node_id, czr::node_discover_event_type::node_entry_added);
					}
				}
			}
		}

		if (node_to_evict)
			evict(node_to_evict, new_node);
	}
}

void czr::node_discover::evict(std::shared_ptr<czr::node_entry> const & node_to_evict, std::shared_ptr<czr::node_entry> const & new_node)
{
	if (!socket->is_open())
		return;

	unsigned evicts = 0;
	{
		std::lock_guard<std::mutex> lock(evictions_mutex);
		czr::eviction_entry eviction_entry{ new_node->node_id, std::chrono::steady_clock::now() };
		evictions.emplace(node_to_evict->node_id, eviction_entry);
		evicts = evictions.size();
	}

	if (evicts == 1)
		do_check_evictions();
	if (node_to_evict)
		ping(node_to_evict->endpoint);
}

void czr::node_discover::do_check_evictions()
{
	eviction_check_timer = std::make_unique<ba::deadline_timer>(io_service);
	eviction_check_timer->expires_from_now(eviction_check_interval);
	eviction_check_timer->async_wait([this](boost::system::error_code const& ec)
	{
		if (ec)
			BOOST_LOG_TRIVIAL(debug) << "Check Evictions timer was probably cancelled: " << ec.value() << " " << ec.message();

		if (ec.value() == boost::asio::error::operation_aborted)
			return;

		bool evictions_remain = false;
		std::list<std::shared_ptr<czr::node_entry>> drop;
		{
			std::lock_guard<std::mutex> evictions_lock(evictions_mutex);
			std::lock_guard<std::mutex> nodes_lock(nodes_mutex);
			for (auto & e : evictions)
				if (std::chrono::steady_clock::now() - e.second.evicted_time > req_timeout)
					if (nodes.count(e.second.new_node_id))
						drop.push_back(nodes[e.second.new_node_id]);
			evictions_remain = (evictions.size() - drop.size() > 0);
		}

		drop.unique();
		for (auto n : drop)
			drop_node(n);

		if (evictions_remain)
			do_check_evictions();
	});
}

void czr::node_discover::process_events()
{
	if (node_event_handler)
		node_event_handler->process_events();
}

void czr::node_discover::set_event_handler(czr::node_discover_event_handler * handler)
{
	node_event_handler.reset(handler);
}
