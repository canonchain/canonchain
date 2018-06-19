#pragma once

#include <czr/common.hpp>
#include <czr/rlp/RLP.h>

#include <boost/asio.hpp>

#include <bitset>

#include <xxhash/xxhash.h>

namespace czr
{
using endpoint = boost::asio::ip::udp::endpoint;
bool parse_port (std::string const &, uint16_t &);
}
static uint64_t endpoint_hash_raw (czr::endpoint const & endpoint_a)
{
	assert (endpoint_a.address ().is_v6 ());
	czr::uint128_union address;
	address.bytes = endpoint_a.address ().to_v6 ().to_bytes ();
	XXH64_state_t hash;
	XXH64_reset (&hash, 0);
	XXH64_update (&hash, address.bytes.data (), address.bytes.size ());
	auto port (endpoint_a.port ());
	XXH64_update (&hash, &port, sizeof (port));
	auto result (XXH64_digest (&hash));
	return result;
}

namespace std
{
template <size_t size>
struct endpoint_hash
{
};
template <>
struct endpoint_hash<8>
{
	size_t operator() (czr::endpoint const & endpoint_a) const
	{
		return endpoint_hash_raw (endpoint_a);
	}
};
template <>
struct endpoint_hash<4>
{
	size_t operator() (czr::endpoint const & endpoint_a) const
	{
		uint64_t big (endpoint_hash_raw (endpoint_a));
		uint32_t result (static_cast<uint32_t> (big) ^ static_cast<uint32_t> (big >> 32));
		return result;
	}
};
template <>
struct hash<czr::endpoint>
{
	size_t operator() (czr::endpoint const & endpoint_a) const
	{
		endpoint_hash<sizeof (size_t)> ehash;
		return ehash (endpoint_a);
	}
};
}
namespace boost
{
template <>
struct hash<czr::endpoint>
{
	size_t operator() (czr::endpoint const & endpoint_a) const
	{
		std::hash<czr::endpoint> hash;
		return hash (endpoint_a);
	}
};
}

namespace czr
{

class joint
{
public:
	joint(std::shared_ptr<czr::block>);
	joint (bool & error_a, dev::RLP const & r);
	void stream_RLP(dev::RLPStream & s) const;

	std::shared_ptr<czr::block> block;
	czr::summary_hash summary_hash;
	std::vector<block_hash> block_skiplist;
	bool is_fork;
	bool is_invalid;
	bool is_fail;
	czr::account_state_hash from_state;
	czr::account_state_hash to_state;
};

enum class validate_result_codes
{
	ok, // Hasn't been seen before, signed correctly
	old, // Already seen and was valid
	missing_hash_tree_summary,
	missing_parents_and_previous,
	exec_timestamp_too_late,
	invalid_block,
	known_invalid_block,
	invalid_message,
};

class validate_result
{
public:
	czr::validate_result_codes code;
	std::string err_msg;
	std::vector<czr::block_hash> missing_parents_and_previous;
	czr::account account;
	czr::amount amount;
};

/**
 * Returns seconds passed since unix epoch (posix time)
 */
inline uint64_t seconds_since_epoch ()
{
	return std::chrono::duration_cast<std::chrono::seconds> (std::chrono::system_clock::now().time_since_epoch()).count();
}

inline uint64_t future_from_epoch(std::chrono::seconds sec)
{
	return std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + sec).time_since_epoch()).count();
}

}
