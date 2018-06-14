#include "common.hpp"

czr::p2p_config::p2p_config() :
	port(czr::p2p_default_port),
	max_peers(czr::p2p_default_max_peers)
{
}

void czr::p2p_config::serialize_json(boost::property_tree::ptree & tree_a) const
{
	tree_a.put("version", "1");
	tree_a.put("host", listen_ip);
	tree_a.put("port", std::to_string(port));
	tree_a.put("max_peers", std::to_string(max_peers));
	boost::property_tree::ptree preconfigured_peers_l;
	for (auto i(bootstrap_nodes.begin()), n(bootstrap_nodes.end()); i != n; ++i)
	{
		boost::property_tree::ptree entry;
		entry.put("", *i);
		preconfigured_peers_l.push_back(std::make_pair("", entry));
	}
	tree_a.add_child("bootstrap_nodes", preconfigured_peers_l);
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
		listen_ip = (tree_a.get<std::string>("host"));
		auto port_l(tree_a.get<std::string>("port"));
		auto max_peers_l(tree_a.get<std::string>("max_peers"));
		auto preconfigured_peers_l(tree_a.get_child("bootstrap_nodes"));
		bootstrap_nodes.clear();
		for (auto i(preconfigured_peers_l.begin()), n(preconfigured_peers_l.end()); i != n; ++i)
		{
			auto bootstrap_peer(i->second.get<std::string>(""));
			bootstrap_nodes.push_back(bootstrap_peer);
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