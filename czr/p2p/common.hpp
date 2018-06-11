#pragma once

#include <czr/p2p/peer.hpp>
#include <czr/config.hpp>
#include <czr/lib/numbers.hpp>
#include <czr/rlp/Common.h>
#include <czr/rlp/RLP.h>

#include <vector>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace bi = boost::asio::ip;

//std::hash for asio::adress
namespace std
{
	template <> struct hash<bi::address>
	{
		size_t operator()(bi::address const& _a) const
		{
			if (_a.is_v4())
				return std::hash<unsigned long>()(_a.to_v4().to_ulong());
			if (_a.is_v6())
			{
				auto const& range = _a.to_v6().to_bytes();
				return boost::hash_range(range.begin(), range.end());
			}
			if (_a.is_unspecified())
				return static_cast<size_t>(0x3487194039229152ull);  // Chosen by fair dice roll, guaranteed to be random
			return std::hash<std::string>()(_a.to_string());
		}
	};

}

namespace czr
{
	using node_id = uint256_union;

	uint16_t const p2p_version(0);
	boost::posix_time::milliseconds const handshake_timeout = boost::posix_time::milliseconds(5000);
	size_t const message_header_size(4);
	size_t const max_tcp_packet_size(4 * 1024 * 1024);

	enum class packet_type
	{
		handshake = 0,
		disconect = 1,
		ping = 2,
		pong = 3,


		user_packet = 0x10
	};

	class p2p_config
	{
	public:
		p2p_config();
		void serialize_json(boost::property_tree::ptree &) const;
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		std::string host;
		uint16_t port;
		uint32_t max_peers;
		std::vector<std::string> preconfigured_peers;

		static uint16_t const default_port = czr::czr_network == czr::czr_networks::czr_live_network ? 7075 : 54000;
	};

	class capability_desc
	{
	public:
		capability_desc(std::string const & name_a, uint32_t const & version_a);
		capability_desc(dev::RLP const & r);
		void stream_RLP(dev::RLPStream & s);

		bool operator==(czr::capability_desc const & other_a) const;
		bool operator<(czr::capability_desc const & other_a) const;

		std::string name;
		uint32_t version;

	};

	class peer;

	class icapability
	{
	public:
		icapability(czr::capability_desc const & desc_a, unsigned const & packet_count);
		virtual void on_connect(czr::peer peer_a) = 0;
		virtual bool read_packet(unsigned const & type, dev::RLP const & r) = 0;
		unsigned packet_count() const;

		czr::capability_desc desc;
	private:
		unsigned _packet_count;
	};

	class peer_capability
	{
	public:
		peer_capability(czr::capability_desc const & desc_a, unsigned const & offset_a, std::shared_ptr<czr::icapability> const & cap_a);
		czr::capability_desc desc;
		unsigned offset;
		std::shared_ptr<czr::icapability> cap;
	};

	class handshake_message
	{
	public:
		handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, czr::node_id const & node_id_a, std::list<capability_desc> const & caps_a);
		handshake_message(dev::RLP const & r);
		void stream_RLP(dev::RLPStream & s);

		uint16_t version;
		czr::czr_networks network;
		czr::node_id node_id;
		std::list<capability_desc> cap_descs;
	};
}