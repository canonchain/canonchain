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
		void run(boost::filesystem::path const &, boost::program_options::variables_map &vm);
	};
	class daemon_config
	{
	public:
		daemon_config(boost::filesystem::path const &);
		bool deserialize_json(bool &, boost::property_tree::ptree &);
		bool upgrade_json(unsigned, boost::property_tree::ptree &);
		void serialize_json(boost::property_tree::ptree &);
		void readfile2bytes(dev::bytes &,boost::filesystem::path const&);
		void writebytes2file(dev::bytes &, boost::filesystem::path const &);
		void readfile2string(std::string & ret, boost::filesystem::path const & filepath);
		void writestring2file(std::string const & str, boost::filesystem::path const & filepath);
		bool rpc_enable;
		czr::rpc_config rpc;
		czr::node_config node;
		bool witness_enable;
	};
}
