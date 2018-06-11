#pragma once

#include <czr/lib/numbers.hpp>
#include <czr/rlp/RLP.h>


#include <array>

#include <boost/asio.hpp>
#include <boost/integer/static_log2.hpp>

namespace ba = boost::asio;
namespace bi = boost::asio::ip;

namespace czr
{
	using node_id = uint256_union;

	// Constants for Kademlia, derived from address space.

	static unsigned const s_address_byte_size = 32;							//< Size of address type in bytes.
	static unsigned const s_bits = 8 * s_address_byte_size;					//< Denoted by n in [Kademlia].
	static unsigned const s_bins = s_bits - 1;								//< Size of buckets (excludes root, which is us).

	static unsigned const s_bucket_size = 16;								//< Denoted by k in [Kademlia]. Number of nodes stored in each bucket.
	static unsigned const s_alpha = 3;										//< Denoted by \alpha in [Kademlia]. Number of concurrent FindNode requests.

	enum RLP_append
	{
		stream_list,
		stream_inline
	};

	class node_endpoint
	{
	public:
		node_endpoint() {}

		node_endpoint(bi::address addr_a, uint16_t udp_a, uint16_t tcp_a) :
			address(addr_a),
			udp_port(udp_a), 
			tcp_port(tcp_a) 
		{
		}

		void stream_RLP(dev::RLPStream & s, RLP_append append = czr::RLP_append::stream_list) const
		{
			if (append == czr::RLP_append::stream_list)
				s.appendList(3);
			if (address.is_v4())
				s << dev::bytesConstRef(&address.to_v4().to_bytes()[0], 4);
			else if (address.is_v6())
				s << dev::bytesConstRef(&address.to_v6().to_bytes()[0], 16);
			else
				s << dev::bytes();
			s << udp_port << tcp_port;
		}

		void interpret_RLP(dev::RLP const & r)
		{
			if (r[0].size() == 4)
				address = bi::address_v4(*(bi::address_v4::bytes_type*)r[0].toBytes().data());
			else if (r[0].size() == 16)
				address = bi::address_v6(*(bi::address_v6::bytes_type*)r[0].toBytes().data());
			else
				address = bi::address();
			udp_port = r[1].toInt<uint16_t>();
			tcp_port = r[2].toInt<uint16_t>();
		}

		operator bi::udp::endpoint() const { return bi::udp::endpoint(address, udp_port); }
		operator bi::tcp::endpoint() const { return bi::tcp::endpoint(address, tcp_port); }

		bi::address address;
		uint16_t udp_port = 0;
		uint16_t tcp_port = 0;
	};

	class node_info
	{
	public:
		node_info(czr::node_id const & node_id_a, czr::node_endpoint const & endpoint_a):
			node_id(node_id_a),
			endpoint(endpoint_a)
		{
		}

		node_info(czr::node_info const & other):
			node_id(other.node_id),
			endpoint(other.endpoint)
		{
		
		}

		czr::node_id node_id;
		czr::node_endpoint endpoint;
	};

	class node_entry : public node_info
	{
	public:
		node_entry(czr::node_id const & my_node_id, czr::node_id const & remote_node_id, czr::node_endpoint const & endpoint_a) :
			node_info(remote_node_id, endpoint_a),
			distance(czr::node_entry::calc_distance(my_node_id, remote_node_id)),
			pending(true)
		{
		}
		unsigned distance;	//< Node's distance (xor of _src as integer).
		bool pending;				//< Node will be ignored until Pong is received

		static unsigned calc_distance(czr::node_id const & a, czr::node_id const & b)
		{
			uint256_t d = (a ^ b).number();
			unsigned ret; 
			for (ret = 0; d >>= 1; ++ret) {};
			return ret;
		}
	};

	class node_bucket
	{
	public:
		unsigned distance;
		std::list<std::weak_ptr<czr::node_entry>> nodes;
	};

	class node_table
	{
	public:
		node_table(czr::node_id const & node_id_a);
		std::vector<std::shared_ptr<czr::node_entry>> nearest_node_entries(czr::node_id const & node_id_a);
		std::shared_ptr<czr::node_entry> get_node(czr::node_id const & node_id);
		bool have_node(czr::node_id const & node_id);
		void add_node(czr::node_info const & node_info);
		void active_node(czr::node_id const & node_id, bi::udp::endpoint const & from);
		void drop_node(czr::node_id const & node_id);

		
		czr::node_id my_node_id;
		std::array<czr::node_bucket, s_bins> buckets;

		std::mutex nodes_mutex;
		std::unordered_map<czr::node_id, std::shared_ptr<czr::node_entry>> nodes;	
	};
}