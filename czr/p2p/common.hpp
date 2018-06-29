#pragma once

#include <czr/common.hpp>
#include <czr/config.hpp>
#include <czr/lib/numbers.hpp>
#include <czr/rlp/Common.h>
#include <czr/rlp/RLP.h>

#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include<boost/log/trivial.hpp>
#include <boost/asio.hpp>

namespace ba = boost::asio;
namespace bi = boost::asio::ip;

namespace czr
{
	namespace p2p
	{
		using node_id = czr::uint256_union;
		using hash256 = czr::uint256_union;

		static uint16_t const version(0);
		static uint16_t const default_port = czr::czr_network == czr::czr_networks::czr_live_network ? 30606 : 40606;
		static uint16_t const default_max_peers(25);

		static size_t const tcp_header_size(4);
		static size_t const max_tcp_packet_size(4 * 1024 * 1024);

		class p2p_config
		{
		public:
			p2p_config();
			void serialize_json(boost::property_tree::ptree &) const;
			bool deserialize_json(bool &, boost::property_tree::ptree &);
			std::string listen_ip;
			uint16_t port;
			uint32_t max_peers;
			std::vector<std::string> bootstrap_nodes;
		};

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

			node_endpoint(dev::RLP const & r)
			{
				interpret_RLP(r);
			}

			void stream_RLP(dev::RLPStream & s, RLP_append append = RLP_append::stream_list) const
			{
				if (append == RLP_append::stream_list)
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

			operator bool() const { return !address.is_unspecified() && udp_port > 0 && tcp_port > 0; }

			bool operator==(node_endpoint const& other) const {
				return address == other.address && udp_port == other.udp_port && tcp_port == other.tcp_port;
			}
			bool operator!=(node_endpoint const& other) const {
				return !operator==(other);
			}

			bi::address address;
			uint16_t udp_port = 0;
			uint16_t tcp_port = 0;
		};

		class node_info
		{
		public:
			node_info(node_id const & node_id_a, node_endpoint const & endpoint_a) :
				id(node_id_a),
				endpoint(endpoint_a)
			{
			}

			node_info(node_info const & other) :
				id(other.id),
				endpoint(other.endpoint)
			{

			}

			node_id id;
			node_endpoint endpoint;
		};
	}
}