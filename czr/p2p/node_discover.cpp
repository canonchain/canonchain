#include "node_discover.hpp"

#include<boost/log/trivial.hpp>

czr::node_discover::node_discover(boost::asio::io_service & io_service_a, czr::keypair const & alias_a, czr::node_endpoint const & endpoint):
	io_service(io_service_a),
	node_info(alias_a.pub, endpoint),
	secret(alias_a.prv.data),
	table(),
	socket(std::make_unique<bi::udp::socket>(io_service_a)),
	endpoint((bi::udp::endpoint)endpoint)
{
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
			czr::send_udp_datagram datagram(n->endpoint, node_info.node_id);
			datagram.add_packet_and_sign(secret, p);

			//todo:findNodeTimeout
			//DEV_GUARDED(x_findNodeTimeout)
			//	m_findNodeTimeout.push_back(make_pair(r->id, chrono::steady_clock::now()));
			send(datagram);
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
	discover_timer->expires_from_now(req_timeout);
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

void czr::node_discover::handle_receive(bi::udp::endpoint const & recv_endpoint_a, dev::bytesConstRef const & data)
{
	//todo:
}

std::unique_ptr<czr::recv_udp_datagram> czr::node_discover::interpret_packet(bi::udp::endpoint const & from, dev::bytesConstRef data)
{
	std::unique_ptr<czr::recv_udp_datagram> datagram;
	// hash + node id + sig + packet type + packet (smallest possible packet is empty neighbours packet which is 3 bytes)
	if (data.size() < sizeof(czr::hash256) + sizeof(czr::node_id) + sizeof(czr::signature) + 1 + 3)
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet (too small) from "	<< from.address().to_string() << ":" << from.port();
		return datagram;
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
		return datagram;
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
		return datagram;
	}

	try
	{
		datagram->interpret(from, from_node_id, rlp_cref);
	}
	catch (std::exception const & e)
	{
		BOOST_LOG_TRIVIAL(debug) << "Invalid packet format " << from.address().to_string() << ":" << from.port() << " message:" <<e.what();
		return datagram;
	}

	return datagram;
}

void czr::node_discover::send(czr::send_udp_datagram const & datagram)
{
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