#include <czr/node/node.hpp>
#include <czr/node/rpc.hpp>

namespace czr_daemon
{
	class daemon
	{
	public:
		void run(boost::filesystem::path const &);
	};
	class daemon_config
	{
	public:
		daemon_config(boost::filesystem::path const &);
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		bool upgrade_json(unsigned, boost::property_tree::ptree &);
		void serialize_json(boost::property_tree::ptree &);
		bool rpc_enable;
		czr::rpc_config rpc;
		czr::node_config node;
		bool opencl_enable;
		czr::opencl_config opencl;
	};
}
