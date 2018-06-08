#include "node_discover.hpp"

#include<boost/log/trivial.hpp>

czr::node_discover::node_discover(boost::asio::io_service & io_service_a, czr::node_id const & node_id_a, czr::node_endpoint const & endpoint):
	io_service(io_service_a),
	node_info(node_id_a, endpoint),
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
			auto r = nearest[i];
			tried.push_back(r);
			//todo:send find node
			//FindNode p(r->endpoint, _node);
			//p.sign(m_secret);
			//DEV_GUARDED(x_findNodeTimeout)
			//	m_findNodeTimeout.push_back(make_pair(r->id, chrono::steady_clock::now()));
			//send(p);
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

void czr::node_discover::send(czr::udp_datagram const & datagram)
{
	std::lock_guard<std::mutex> lock(send_queue_mutex);
	send_queue.push_back(datagram);
	if (send_queue.size() == 1)
		do_write();
}

void czr::node_discover::do_write()
{
	const udp_datagram & datagram = send_queue[0];
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