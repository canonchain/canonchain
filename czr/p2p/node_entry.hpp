#pragma once

#include <czr/p2p/common.hpp>

namespace czr
{
	struct node_entry : public node_info
	{
	public:
		node_entry(czr::node_id const & my_node_id, czr::node_id const & remote_node_id, czr::node_endpoint const & endpoint_a) :
			node_info(remote_node_id, endpoint_a),
			distance(czr::node_entry::calc_distance(my_node_id, remote_node_id)),
			pending(true)
		{
		}
		unsigned distance;	//< Node's distance (xor of _src as integer).
		bool pending;				//< Node will be ignored until Pong is received

		static unsigned calc_distance(czr::node_id const & a, czr::node_id const & b)
		{
			uint256_t d = (a ^ b).number();
			unsigned ret;
			for (ret = 0; d >>= 1; ++ret) {};
			return ret;
		}
	};
}