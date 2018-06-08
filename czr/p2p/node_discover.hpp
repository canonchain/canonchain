#pragma once

#include "node_table.hpp"
#include "common.hpp"

#include <czr/rlp/Common.h>
#include <czr/rlp/RLP.h>

namespace czr
{
	class udp_datagram
	{
	public:
		udp_datagram(bi::udp::endpoint const & endpoint_a, dev::bytes const & data_a) :
			endpoint(endpoint_a),
			data(data_a)
		{
		}

		bi::udp::endpoint endpoint;
		dev::bytes data;
	};

	enum class discover_packet_type
	{
		ping = 1,
		pong = 2,
		find_node = 3,
		neighbours = 4
	};

	class discover_packet
	{
	public:
		discover_packet() :
			timestamp(future_from_epoch(std::chrono::seconds(60)))
		{
		}

		uint32_t future_from_epoch(std::chrono::seconds sec) 
		{ 
			return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + sec).time_since_epoch()).count()); 
		}

		uint32_t timestamp;
	};

	class ping_packet : czr::discover_packet
	{
	public:
		ping_packet(czr::node_endpoint const & source_a, czr::node_endpoint const &  destination_a) :
			discover_packet(),
			source(source_a),
			destination(destination_a)
		{
		}

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(4);
			s << czr::p2p_version;
			source.stream_RLP(s);
			destination.stream_RLP(s);
			s << timestamp;
		}

		void interpret_RLP(dev::bytesConstRef _bytes)
		{
			dev::RLP r(_bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			version = r[0].toInt<uint16_t>();
			source.interpret_RLP(r[1]);
			destination.interpret_RLP(r[2]);
			timestamp = r[3].toInt<uint32_t>();
		}

		uint16_t version;
		czr::node_endpoint source;
		czr::node_endpoint destination;
	};

	class pong_packet : czr::discover_packet
	{
	public:
		pong_packet(czr::node_endpoint const & destination_a, czr::uint256_union const & echo_a) :
			discover_packet(),
			destination(destination_a),
			echo(echo_a)
		{
		}

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(3);
			destination.stream_RLP(s);
			s << echo;
			s << timestamp;
		}

		void interpret_RLP(dev::bytesConstRef _bytes)
		{
			dev::RLP r(_bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			destination.interpret_RLP(r[0]);
			echo = (czr::uint256_union)r[1];
			timestamp = r[2].toInt<uint32_t>();
		}

		czr::uint256_union echo;
		czr::node_endpoint destination;
	};

	class find_node_packet : czr::discover_packet
	{
	public:
		find_node_packet(czr::uint256_union const & target_a) :
			discover_packet(),
			target(target_a)
		{
		}

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(2); s << target << timestamp;
		}
		void interpret_RLP(dev::bytesConstRef bytes)
		{
			dev::RLP r(bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			target = (czr::uint256_union)r[0];
			timestamp = r[1].toInt<uint32_t>();
		}

		czr::uint256_union target;
	};

	class neighbour
	{
	public:
		neighbour(czr::node_info const & node_info_a) :
			endpoint(node_info_a.endpoint),
			node_id(node_info_a.node_id)
		{

		}

		neighbour(dev::RLP const & r)
		{
			endpoint.interpret_RLP(r);
			node_id = (czr::node_id)r[3];
		}

		czr::node_endpoint endpoint;
		czr::node_id node_id;

		void streamRLP(dev::RLPStream & s) const
		{
			s.appendList(4);
			endpoint.stream_RLP(s, czr::RLP_append::stream_inline);
			s << node_id;
		}
	};

	class neighbours_packet : discover_packet
	{
	public:
		neighbours_packet(std::vector<std::shared_ptr<czr::node_entry>> const& nearest_a, unsigned offset_a = 0, unsigned limit_a = 0) :
			discover_packet()
		{
			auto limit = limit_a ? std::min(nearest_a.size(), (size_t)(offset_a + limit_a)) : nearest_a.size();
			for (auto i = offset_a; i < limit; i++)
				neighbours.push_back(neighbour(*nearest_a[i]));
		}

		void stream_RLP(dev::RLPStream& _s) const
		{
			_s.appendList(2);
			_s.appendList(neighbours.size());
			for (auto const& n : neighbours)
				n.streamRLP(_s);
			_s << timestamp;
		}

		void interpret_RLP(dev::bytesConstRef bytes)
		{
			dev::RLP r(bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			for (auto const & n : r[0])
				neighbours.emplace_back(n);
			timestamp = r[1].toInt<uint32_t>();
		}

		std::vector<neighbour> neighbours;
	};

	class node_discover :std::enable_shared_from_this<czr::node_discover>
	{
	public:
		node_discover(boost::asio::io_service & io_service_a, czr::node_id const & node_id_a, czr::node_endpoint const & endpoint);

		void start();
		void discover_loop();
		void do_discover(czr::node_id const & rand_node_id, unsigned const & round = 0, std::shared_ptr<std::set<std::shared_ptr<czr::node_entry>>> tried = nullptr);
		void receive_loop();
		void handle_receive(bi::udp::endpoint const & recv_endpoint_a, dev::bytesConstRef const & data);
		void send(czr::udp_datagram const & datagram);
		void do_write();

		ba::io_service & io_service;
		czr::node_info node_info;
		bi::udp::endpoint endpoint;
		czr::node_table table;
		std::unique_ptr<bi::udp::socket> socket;
		bi::udp::endpoint recv_endpoint;
		std::array<byte, 1028> recv_buffer;
		std::deque<czr::udp_datagram> send_queue;
		std::mutex send_queue_mutex;
		std::unique_ptr<ba::deadline_timer> discover_timer;
	};

	static boost::posix_time::milliseconds const discover_interval = boost::posix_time::milliseconds(7200);
	//How long to wait for requests (evict, find iterations).
	static boost::posix_time::milliseconds const req_timeout = boost::posix_time::milliseconds(300);
	//Max iterations of discover. (discover)
	static unsigned const max_discover_rounds = boost::static_log2<s_bits>::value;	

}