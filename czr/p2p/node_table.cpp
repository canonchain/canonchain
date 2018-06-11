#include "node_table.hpp"

czr::node_table::node_table(czr::node_id const & node_id_a) :
	my_node_id(node_id_a)
{
	for (unsigned i = 0; i < s_bins; i++)
		buckets[i].distance = i;
}

std::vector<std::shared_ptr<czr::node_entry>> czr::node_table::nearest_node_entries(czr::node_id const & node_id_a)
{
	//todo: nearest_node_entries;
	return std::vector<std::shared_ptr<czr::node_entry>>();
}
