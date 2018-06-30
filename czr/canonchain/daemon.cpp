#include <czr/canonchain/daemon.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp> 
#include <fstream>
#include <iostream>
#include <thread>
#include <czr/node/working.hpp>
#include <czr/node/witness.hpp>

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
	std::ifstream in;
	in.open(filepath.string(), std::ios_base::in | std::ios_base::binary);
	if (in.is_open())
	{
		size_t const c_elementSize = sizeof(typename dev::bytes::value_type);
		in.seekg(0, in.end);
		size_t length = in.tellg();
		if (length)
		{
			in.seekg(0, in.beg);
			ret.resize((length + c_elementSize - 1) / c_elementSize);
			in.read(const_cast<char*>(reinterpret_cast<char const*>(ret.data())), length);
		}
		in.close();
	}
}

void czr_daemon::daemon_config::writebytes2file(dev::bytes & bytes,boost::filesystem::path const&filepath)
{
	std::ofstream out;
	out.open(filepath.string(), std::ios_base::out | std::ios_base::binary);
	if(out.is_open())
	{
		out.write(reinterpret_cast<char const*>(bytes.data()), bytes.size());
	return ;   
 }	
}

void czr_daemon::daemon_config::readfile2string(std::string & str, boost::filesystem::path const&filepath)
{
	std::ifstream in;
	in.open(filepath.string(), std::ios_base::in);
	if (in.is_open())
	{
		in >> str;
		in.close();
	}
}

void czr_daemon::daemon_config::writestring2file(std::string const & str, boost::filesystem::path const & filepath)
{
	std::ofstream out;
	out.open(filepath.string(), std::ios_base::out | std::ios_base::binary);
	if (out.is_open())
	{
		out << str;
		out.close();
	}
}


void czr_daemon::daemon::run(boost::filesystem::path const &data_path, boost::program_options::variables_map &vm)
{
	boost::filesystem::create_directories(data_path);
	czr_daemon::daemon_config config(data_path);
	auto config_path((data_path / "config.json"));
	std::fstream config_file;
	std::unique_ptr<czr::thread_runner> runner;
	auto error(czr::fetch_object(config, config_path, config_file));
	if (vm.count("rpc_enable")>0)
	{
		config.rpc_enable = true;
	}
	if (vm.count("rpc_enable_control")>0)
	{
		config.rpc.enable_control = true;
	}

	//--witness 	
	bool is_witness(false);
	czr::error_message error_msg;
	std::string account;
	std::string password;
	std::string filename;
	if (vm.count("witness")>0)
	{
		//todo getpassword
		if ((vm.count("account") == 0 && vm.count("file") == 0)|| vm.count("password") == 0)
		{
			error_msg.error = true;
			error_msg.message = "witness need account and password\n ";
			std::cerr << "witness need account or file and password\n ";
			return;
		}
		else
		{
			is_witness = true;
			account = (vm.count("account")>0) ? vm["account"].as<std::string>():"";
			filename = (vm.count("file")>0) ? vm["file"].as<std::string>() : "";
			password = vm["password"].as<std::string>();
		}
	}

	if (!error)
	{
		config.node.logging.init(data_path);
		config_file.close();
		boost::asio::io_service io_service;
		czr::alarm alarm(io_service);
		czr::node_init init;
		try
		{
			//node key
			czr::private_key node_key;

			boost::filesystem::path nodekey_path(data_path / "nodekey");
			std::string nodekey_str;
			config.readfile2string(nodekey_str, data_path / "nodekey");

			bool nodekey_error(node_key.decode_hex(nodekey_str));
			if (nodekey_error)
			{
				czr::random_pool.GenerateBlock(node_key.bytes.data(), node_key.bytes.size());
				config.writestring2file(node_key.to_string(), nodekey_path);
			}

			boost::filesystem::path network_bytes_path(data_path / "network.rlp");
			//get network bytes
			dev::bytesConstRef restore_network_bytes;
			dev::bytes nbytes;
			config.readfile2bytes(nbytes, network_bytes_path);
			restore_network_bytes = &(nbytes);

			//node
			std::shared_ptr<czr::node> node(std::make_shared<czr::node>(init, io_service, data_path, alarm, config.node, node_key, restore_network_bytes));
			if (!init.error)
			{
				//witness node start
				if (is_witness)
				{
					std::shared_ptr<czr::witness> witness_l(std::make_shared<czr::witness>(error_msg, *node, account, password));

					//czr::witness witness_l(error_msg, *node, account, password);
					if (error_msg.error)
					{
						std::cerr << error_msg.message << std::endl;
						return;
					}
					node->start();
					witness_l->start();
				}
				else
				{
					node->start();
				}

				std::unique_ptr<czr::rpc> rpc = get_rpc(io_service, *node, config.rpc);
				if (config.rpc_enable)
				{
					rpc->start();
				}
				else
				{
					BOOST_LOG(node->log) << "RPC is disabled";
				}

				runner = std::make_unique<czr::thread_runner>(io_service, config.node.io_threads);

				signal(SIGABRT, &exit_handler::handle);
				signal(SIGTERM, &exit_handler::handle);
				signal(SIGINT, &exit_handler::handle);

				while (!exit_handler::should_exit())
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));

				//save network bytes
				dev::bytes network_bytes(node->network_bytes());
				config.writebytes2file(network_bytes, network_bytes_path);

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



