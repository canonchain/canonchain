#include "common.hpp"

czr::p2p_config::p2p_config() :
	port(p2p_config::default_port),
	max_peers(25)
{
}

void czr::p2p_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("version", "1");
	tree_a.put("host", host);
	tree_a.put("port", std::to_string(port));
	tree_a.put("max_peers", std::to_string(max_peers));
	boost::property_tree::ptree preconfigured_peers_l;
	for (auto i(preconfigured_peers.begin()), n(preconfigured_peers.end()); i != n; ++i)
	{
		boost::property_tree::ptree entry;
		entry.put("", *i);
		preconfigured_peers_l.push_back(std::make_pair("", entry));
	}
	tree_a.add_child("preconfigured_peers", preconfigured_peers_l);
}

bool czr::p2p_config::deserialize_json(bool & upgraded_a, boost::property_tree::ptree & tree_a)
{
	auto result(false);
	try
	{
		auto version_l(tree_a.get_optional<std::string>("version"));
		if (!version_l)
		{
			tree_a.put("version", "1");
			version_l = "1";
			upgraded_a = true;
		}
		host = (tree_a.get<std::string>("host"));
		auto port_l(tree_a.get<std::string>("port"));
		auto max_peers_l(tree_a.get<std::string>("max_peers"));
		auto preconfigured_peers_l(tree_a.get_child("preconfigured_peers"));
		preconfigured_peers.clear();
		for (auto i(preconfigured_peers_l.begin()), n(preconfigured_peers_l.end()); i != n; ++i)
		{
			auto bootstrap_peer(i->second.get<std::string>(""));
			preconfigured_peers.push_back(bootstrap_peer);
		}

		try
		{
			port = std::stoul(port_l);
			max_peers = std::stoul(max_peers_l);
		}
		catch (std::logic_error const &)
		{
			result = true;
		}
	}
	catch (std::runtime_error const &)
	{
		result = true;
	}
	return result;
}

czr::capability_desc::capability_desc(std::string const & name_a, uint32_t const & version_a) :
	name(name_a),
	version(version_a)
{
}

czr::capability_desc::capability_desc(dev::RLP const & r)
{
	if (r.itemCount() != 2)
		throw std::runtime_error("invalid capability_desc rlp format");
	name = r[0].toString();
	version = r[1].toInt<uint32_t>();
}

void czr::capability_desc::stream_RLP(dev::RLPStream & s)
{
	s.appendList(2) << name << version;
}

bool czr::capability_desc::operator==(capability_desc const & other_a) const
{
	return name == other_a.name && version == other_a.version;
}

bool czr::capability_desc::operator<(capability_desc const & other_a) const
{
	return name < other_a.name ||
		(name == other_a.name && version < other_a.version);
}

czr::icapability::icapability(czr::capability_desc const & desc_a, unsigned const & packet_count_a):
	desc(desc_a),
	_packet_count(packet_count_a)
{
}

unsigned czr::icapability::packet_count() const
{
	return _packet_count;
}

czr::peer_capability::peer_capability(czr::capability_desc const & desc_a, unsigned const & offset_a, std::shared_ptr<czr::icapability> const & cap_a) :
	desc(desc_a),
	offset(offset_a),
	cap(cap_a)
{
}

czr::handshake_message::handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, czr::node_id const & node_id_a, std::list<capability_desc> const & caps_a):
	version(version_a),
	network(network_a),
	node_id(node_id_a),
	cap_descs(caps_a)
{
}

czr::handshake_message::handshake_message(dev::RLP const & r)
{
	if (r.itemCount() != 4)
		throw std::runtime_error("invalid handshake_message rlp format");

	version = (uint16_t)r[0];
	network = (czr::czr_networks)r[1].toInt<uint8_t>();
	node_id = (czr::node_id)r[2];
	auto x = r[3];
	for (auto const & i : r[3])
	{
		cap_descs.push_back(czr::capability_desc(i));
	}
}

void czr::handshake_message::stream_RLP(dev::RLPStream & s)
{
	s.appendList(4) << version << (uint8_t)network << node_id;
	s.appendList(cap_descs.size());
	for (auto & desc : cap_descs)
		desc.stream_RLP(s);
}
