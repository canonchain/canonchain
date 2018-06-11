#pragma once

#include "node_table.hpp"
#include "common.hpp"

#include <czr/lib/numbers.hpp>
#include <czr/rlp/Common.h>
#include <czr/rlp/RLP.h>

#include <blake2/blake2.h>
#include <ed25519-donna/ed25519.h>

namespace czr
{
	using hash256 = uint256_union;

	static czr::hash256 blake2b_hash(dev::bytesConstRef const & bytes)
	{
		czr::hash256 result;
		blake2b_state hash_l;
		auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
		assert(status == 0);

		if (bytes.size() > 0)
			blake2b_update(&hash_l, bytes.data(), bytes.size());

		status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
		assert(status == 0);
		return result;
	}

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

		uint64_t tcp_port;
		uint16_t version;
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

		static size_t const max_size = 57;
	};

	class neighbours_packet : public discover_packet
	{
	public:
		neighbours_packet(czr::node_id const & node_id_a):
			discover_packet(node_id_a)
		{
		}

		neighbours_packet(czr::node_id const & node_id_a, std::vector<std::shared_ptr<czr::node_entry>> const& nearest_a, unsigned offset_a = 0, unsigned limit_a = 0) :
			discover_packet(node_id_a)
		{
			auto limit = limit_a ? std::min(nearest_a.size(), (size_t)(offset_a + limit_a)) : nearest_a.size();
			for (auto i = offset_a; i < limit; i++)
				neighbours.push_back(neighbour(*nearest_a[i]));
		}

		czr::discover_packet_type packet_type() const { return czr::discover_packet_type::neighbours; };

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

	class send_udp_datagram
	{
	public:
		send_udp_datagram(bi::udp::endpoint const & endpoint_a) :
			endpoint(endpoint_a)
		{
		}

		czr::hash256 add_packet_and_sign(czr::private_key const & prv_a, czr::discover_packet const & packet_a)
		{
			assert((byte)packet_a.packet_type());

			//rlp: type || data
			dev::RLPStream s;
			s.appendRaw(dev::bytes(1, (byte)packet_a.packet_type()));
			packet_a.stream_RLP(s);
			dev::bytes const & rlp(s.out());
			dev::bytesConstRef rlp_cref(&rlp);

			//rlp hash : H(type || data)
			czr::hash256 rlp_hash(czr::blake2b_hash(rlp_cref));

			//rlp sig : S(H(type||data))
			czr::signature rlp_sig(czr::sign_message(prv_a, packet_a.node_id, rlp_hash));

			//data:  H( node id || rlp sig || rlp ) || node id || rlp sig || rlp 
			data.resize(sizeof(czr::hash256) + sizeof(czr::node_id) + sizeof(czr::signature) + rlp.size());
			dev::bytesRef data_hash_ref(&data[0], sizeof(czr::hash256));
			dev::bytesRef data_node_id_ref(&data[sizeof(czr::hash256)], sizeof(czr::node_id));
			dev::bytesRef data_sig_ref(&data[sizeof(czr::hash256) + sizeof(czr::node_id)], sizeof(czr::signature));
			dev::bytesRef data_rlp_ref(&data[sizeof(czr::hash256) + sizeof(czr::node_id) + sizeof(czr::signature)], rlp_cref.size());

			dev::bytesConstRef node_id_cref(packet_a.node_id.bytes.data(), packet_a.node_id.bytes.size());
			node_id_cref.copyTo(data_node_id_ref);

			dev::bytesConstRef sig_cref(rlp_sig.bytes.data(), rlp_sig.bytes.size());
			sig_cref.copyTo(data_sig_ref);

			rlp_cref.copyTo(data_rlp_ref);

			dev::bytesConstRef bytes_to_hash(&data[sizeof(czr::hash256)], data.size() - sizeof(czr::hash256));
			czr::hash256 hash(czr::blake2b_hash(bytes_to_hash));

			dev::bytesConstRef hash_cref(hash.bytes.data(), hash.bytes.size());
			hash_cref.copyTo(data_hash_ref);

			return rlp_hash;
		}

		bi::udp::endpoint endpoint;
		dev::bytes data;
	};

	struct eviction_entry
	{
		czr::node_id new_node_id;
		std::chrono::steady_clock::time_point evicted_time;
	};

	static boost::posix_time::milliseconds const discover_interval = boost::posix_time::milliseconds(7200);
	//How long to wait for requests (evict, find iterations).
	static std::chrono::milliseconds const req_timeout = std::chrono::milliseconds(300);
	//Max iterations of discover. (discover)
	static unsigned const max_discover_rounds = boost::static_log2<s_bits>::value;

	static size_t const max_udp_packet_size = 1028;

	class node_discover :std::enable_shared_from_this<czr::node_discover>
	{
	public:
		node_discover(boost::asio::io_service & io_service_a, czr::keypair const & alias_a, czr::node_endpoint const & endpoint);
		~node_discover();

		void start();
		void discover_loop();
		void do_discover(czr::node_id const & rand_node_id, unsigned const & round = 0, std::shared_ptr<std::set<std::shared_ptr<czr::node_entry>>> tried = nullptr);
		void receive_loop();
		void handle_receive(bi::udp::endpoint const & recv_endpoint_a, dev::bytesConstRef const & data);
		std::unique_ptr<czr::discover_packet> interpret_packet(bi::udp::endpoint const & from, dev::bytesConstRef data);
		void send(bi::udp::endpoint const & to_endpoint, czr::discover_packet const & packet);
		void do_write();

		ba::io_service & io_service;
		czr::node_info node_info;
		czr::private_key secret;
		bi::udp::endpoint endpoint;
		czr::node_table table;

		std::unique_ptr<bi::udp::socket> socket;

		bi::udp::endpoint recv_endpoint;
		std::array<byte, czr::max_udp_packet_size> recv_buffer;

		std::deque<czr::send_udp_datagram> send_queue;
		std::mutex send_queue_mutex;

		std::unique_ptr<ba::deadline_timer> discover_timer;

		std::unordered_map<czr::node_id, czr::eviction_entry> evictions;
		std::mutex evictions_mutex;

		//List of pending pings where node entry wasn't created due to unkown pubk.
		std::unordered_map<bi::address, std::chrono::steady_clock::time_point> pubk_discover_pings;
		std::mutex  pubk_discover_pings_mutex;

		//Timeouts for FindNode requests.
		std::unordered_map<czr::node_id, std::chrono::steady_clock::time_point> find_node_timeouts;
		std::mutex  find_node_timeouts_mutex;

	};
}