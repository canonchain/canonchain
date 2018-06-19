#include <czr/node/node.hpp>
#include <czr/node/rpc.hpp>

namespace
{
	class exit_handler
	{
	public:
		static void handle(int) { _should_exit = true; }
		static bool should_exit() { return _should_exit; }

	private:
		static bool _should_exit;
	};

	bool exit_handler::_should_exit = false;
}

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
		int  readfile2bytes(dev::bytes &,boost::filesystem::path const&);
	    int  writebytes2file(dev::bytes &, boost::filesystem::path const &);
		bool rpc_enable;
		czr::rpc_config rpc;
		czr::node_config node;
		czr::p2p::p2p_config p2p;
		bool witness_enable;
	};
}
