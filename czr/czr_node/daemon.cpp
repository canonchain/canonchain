#include <czr/czr_node/daemon.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <iostream>
#include <czr/node/working.hpp>
#include <czr/p2p/host.hpp>

czr_daemon::daemon_config::daemon_config(boost::filesystem::path const & application_path_a) :
	rpc_enable(false)
{
}

void czr_daemon::daemon_config::serialize_json(boost::property_tree::ptree & tree_a)
{
	tree_a.put("version", "1");

	tree_a.put("rpc_enable", rpc_enable);
	boost::property_tree::ptree rpc_l;
	rpc.serialize_json(rpc_l);

	tree_a.add_child("rpc", rpc_l);
	boost::property_tree::ptree node_l;
	node.serialize_json(node_l);
	tree_a.add_child("node", node_l);

	boost::property_tree::ptree p2p_l;
	p2p.serialize_json(p2p_l);
	tree_a.add_child("p2p", p2p_l);
}

bool czr_daemon::daemon_config::deserialize_json(bool & upgraded_a, boost::property_tree::ptree & tree_a)
{
	auto error(false);
	try
	{
		if (!tree_a.empty())
		{
			auto version_l(tree_a.get_optional<std::string>("version"));
			if (!version_l)
			{
				tree_a.put("version", "1");
				version_l = "1";
			}
			upgraded_a |= upgrade_json(std::stoull(version_l.get()), tree_a);

			rpc_enable = tree_a.get<bool>("rpc_enable");

			auto rpc_l(tree_a.get_child("rpc"));
			error |= rpc.deserialize_json(rpc_l);

			auto & node_l(tree_a.get_child("node"));
			error |= node.deserialize_json(upgraded_a, node_l);

			auto & p2p_l(tree_a.get_child("p2p"));
			error |= p2p.deserialize_json(upgraded_a, p2p_l);
		}
		else
		{
			upgraded_a = true;
			serialize_json(tree_a);
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

bool czr_daemon::daemon_config::upgrade_json(unsigned version_a, boost::property_tree::ptree & tree_a)
{
	auto result(false);
	return result;
}

void czr_daemon::daemon::run(boost::filesystem::path const & data_path)
{
	boost::filesystem::create_directories(data_path);
	czr_daemon::daemon_config config(data_path);
	auto config_path((data_path / "config.json"));
	std::fstream config_file;
	std::unique_ptr<czr::thread_runner> runner;
	auto error(czr::fetch_object(config, config_path, config_file));
	if (!error)
	{
		config.node.logging.init(data_path);
		config_file.close();
		boost::asio::io_service io_service;
		czr::alarm alarm(io_service);
		czr::node_init init;
		try
		{
			std::list<std::shared_ptr<czr::p2p::icapability>> caps;
			dev::bytesConstRef restore_network_bytes;
			std::shared_ptr<czr::p2p::host> host(std::make_shared<czr::p2p::host>(config.p2p, io_service, caps, restore_network_bytes));
			//auto node(std::make_shared<czr::node>(init, io_service, data_path, alarm, config.node));
			if (!init.error)
			{
				host->start();

				//node->start();
				//std::unique_ptr<czr::rpc> rpc = get_rpc(io_service, *node, config.rpc);
				//if (rpc && config.rpc_enable)
				//{
				//	rpc->start();
				//}
				runner = std::make_unique<czr::thread_runner>(io_service, config.node.io_threads);
				runner->join();
			}
			else
			{
				std::cerr << "Error initializing node\n";
			}
		}
		catch (const std::exception & e)
		{
			std::cerr << "Error while running node (" << e.what() << ")\n";
		}
	}
	else
	{
		std::cerr << "Error deserializing config, path:" << config_path << "\n";
	}
}
