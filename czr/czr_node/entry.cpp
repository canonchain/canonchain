#include <czr/node/node.hpp>
#include <czr/czr_node/daemon.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

int main(int argc, char * const * argv)
{
	boost::program_options::options_description description("Command line options");
	czr::add_node_options(description);

	description.add_options()
		("help", "Print out options")
		("version", "Prints out version")
		("daemon", "Start node daemon");

	boost::program_options::variables_map vm;

	try
	{
		boost::program_options::store(boost::program_options::parse_command_line(argc, argv, description), vm);
		boost::program_options::notify(vm);
	}
	catch (std::exception const & e)
	{
		std::cerr << e.what();
		return -1;
	}

	int result(0);
	boost::filesystem::path data_path = vm.count("data_path") ? boost::filesystem::path(vm["data_path"].as<std::string>()) : czr::working_path();
	if (!czr::handle_node_options(vm))
	{
	}
	else if (vm.count("daemon") > 0)
	{
		czr_daemon::daemon daemon;
		daemon.run(data_path);
	}
	else
	{
		std::cout << description << std::endl;
		result = -1;
	}
	return result;
}
