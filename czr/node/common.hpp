#pragma once

#include <czr/common.hpp>
#include <czr/rlp/RLP.h>

#include <boost/asio.hpp>

#include <bitset>

#include <xxhash/xxhash.h>

namespace czr
{

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
	std::list<czr::block_hash> missing_parents_and_previous;
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

bool parse_port(std::string const &, uint16_t &);
}
