#pragma once

#include <czr/p2p/common.hpp>
#include <czr/p2p/node_entry.hpp>

namespace czr
{
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
		discover_packet(czr::node_id const & node_id_a) :
			node_id(node_id_a),
			timestamp(future_from_epoch(std::chrono::seconds(60)))
		{
		}

		static uint32_t future_from_epoch(std::chrono::seconds sec)
		{
			return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + sec).time_since_epoch()).count());
		}

		static uint32_t seconds_since_epoch()
		{
			return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now()).time_since_epoch()).count());
		}

		bool is_expired() const
		{
			return seconds_since_epoch() > timestamp;
		}

		virtual czr::discover_packet_type packet_type() const = 0;
		virtual void stream_RLP(dev::RLPStream & s) const = 0;
		virtual void interpret_RLP(dev::bytesConstRef bytes) = 0;

		czr::node_id node_id;
		uint32_t timestamp;
	};

	class ping_packet : public czr::discover_packet
	{
	public:
		ping_packet(czr::node_id const & node_id_a) :
			discover_packet(node_id_a)
		{
		}

		ping_packet(czr::node_id const & node_id_a, uint16_t const & tcp_port_a) :
			discover_packet(node_id_a),
			tcp_port(tcp_port_a)
		{
		}

		czr::discover_packet_type packet_type() const { return czr::discover_packet_type::ping; };

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(3);
			s << czr::p2p_version;
			s << tcp_port;
			s << timestamp;
		}

		void interpret_RLP(dev::bytesConstRef _bytes)
		{
			dev::RLP r(_bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			version = r[0].toInt<uint16_t>();
			tcp_port = r[1].toInt<uint16_t>();
			timestamp = r[2].toInt<uint32_t>();
		}

		uint16_t version;
		uint64_t tcp_port;
	};

	class pong_packet : public czr::discover_packet
	{
	public:
		pong_packet(czr::node_id const & node_id_a) :
			discover_packet(node_id_a)
		{

		}

		czr::discover_packet_type packet_type() const { return czr::discover_packet_type::pong; };

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(1);
			s << timestamp;
		}

		void interpret_RLP(dev::bytesConstRef _bytes)
		{
			dev::RLP r(_bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			timestamp = r[0].toInt<uint32_t>();
		}

		czr::node_endpoint destination;
	};

	class find_node_packet : public czr::discover_packet
	{
	public:
		find_node_packet(czr::node_id const & node_id_a) :
			discover_packet(node_id_a)
		{

		}

		find_node_packet(czr::node_id const & node_id_a, czr::hash256 const & target_a) :
			discover_packet(node_id_a),
			target(target_a)
		{
		}

		czr::discover_packet_type packet_type() const { return czr::discover_packet_type::find_node; };

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(2); s << target << timestamp;
		}
		void interpret_RLP(dev::bytesConstRef bytes)
		{
			dev::RLP r(bytes, dev::RLP::AllowNonCanon | dev::RLP::ThrowOnFail);
			target = (czr::node_id)r[0];
			timestamp = r[1].toInt<uint32_t>();
		}

		czr::node_id target;
	};

	class neighbour
	{
	public:
		neighbour(czr::node_entry const & ne) :
			endpoint(ne.endpoint),
			node_id(ne.node_id)
		{

		}

		neighbour(dev::RLP const & r)
		{
			endpoint.interpret_RLP(r);
			node_id = (czr::node_id)r[3];
		}

		czr::node_endpoint endpoint;
		czr::node_id node_id;

		void stream_RLP(dev::RLPStream & s) const
		{
			s.appendList(4);
			endpoint.stream_RLP(s, czr::RLP_append::stream_inline);
			s << node_id;
		}

		static size_t const max_size = 57;
	};

	class neighbours_packet : public discover_packet
	{
	public:
		neighbours_packet(czr::node_id const & node_id_a) :
			discover_packet(node_id_a)
		{
		}

		neighbours_packet(czr::node_id const & node_id_a, std::vector<std::shared_ptr<czr::node_entry>> const& nearest_a, unsigned offset_a = 0, unsigned limit_a = 0) :
			discover_packet(node_id_a)
		{
			auto limit = limit_a ? std::min(nearest_a.size(), (size_t)(offset_a + limit_a)) : nearest_a.size();
			for (auto i = offset_a; i < limit; i++)
				neighbours.push_back(czr::neighbour(*nearest_a[i]));
		}

		czr::discover_packet_type packet_type() const { return czr::discover_packet_type::neighbours; };

		void stream_RLP(dev::RLPStream& _s) const
		{
			_s.appendList(2);
			_s.appendList(neighbours.size());
			for (auto const& n : neighbours)
				n.stream_RLP(_s);
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
}