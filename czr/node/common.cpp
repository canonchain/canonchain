
#include <czr/node/common.hpp>
#include <czr/node/wallet.hpp>

bool czr::parse_port(std::string const & string_a, uint16_t & port_a)
{
	bool result;
	size_t converted;
	port_a = std::stoul(string_a, &converted);
	result = converted != string_a.size() || converted > std::numeric_limits<uint16_t>::max();
	return result;
}
