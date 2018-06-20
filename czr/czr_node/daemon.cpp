#include <czr/czr_node/daemon.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <iostream>
#include <thread>
#include <czr/node/working.hpp>

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


void czr_daemon::daemon_config::readfile2bytes(dev::bytes &ret, boost::filesystem::path const&filepath)
{
	//read2bytes
	auto toopenfile((filepath / "node.rlp"));
	std::ifstream  in;
	std::string str;
	in.open(toopenfile.string(), std::ios_base::in | std::ios_base::binary);
	if (in.is_open())
	{ 

		size_t const c_elementSize = sizeof(typename dev::bytes::value_type);
		in.seekg(0, in.end);
		size_t length = in.tellg();
		if(length)
		{
			in.seekg(0, in.beg);
			ret.resize((length + c_elementSize - 1) / c_elementSize);
			in.read(const_cast<char*>(reinterpret_cast<char const*>(ret.data())), length);
		}
		in.close();
	}
	return ;
}

void czr_daemon::daemon_config::writebytes2file(dev::bytes & bytes,boost::filesystem::path const&filepath)
{
	
	auto toopenfile((filepath / "node.rlp"));
	std::ofstream out;
	out.open(toopenfile.string(), std::ios_base::out | std::ios_base::binary);
	if(out.is_open())
	{
		out.write(reinterpret_cast<char const*>(bytes.data()), bytes.size());
		out.close();	   
	}	
	return ;
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
			//get network bytes
			dev::bytesConstRef restore_network_bytes;
			dev::bytes nbytes;
			config.readfile2bytes(nbytes, data_path);
			restore_network_bytes = &(nbytes);

			//node
			std::shared_ptr<czr::node> node(std::make_shared<czr::node>(init, io_service, data_path, alarm, config.node, restore_network_bytes));
			if (!init.error)
			{
				node->start();

				std::unique_ptr<czr::rpc> rpc = get_rpc(io_service, *node, config.rpc);
				if (rpc && config.rpc_enable)
				{
					rpc->start();
				}
				runner = std::make_unique<czr::thread_runner>(io_service, config.node.io_threads);

				signal(SIGABRT, &exit_handler::handle);
				signal(SIGTERM, &exit_handler::handle);
				signal(SIGINT, &exit_handler::handle);
				
				while (!exit_handler::should_exit())
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));

				//save network bytes
				dev::bytes network_bytes(node->network_bytes());
				config.writebytes2file(network_bytes, data_path);

				node->stop();
				io_service.stop();

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



