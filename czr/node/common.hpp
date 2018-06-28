#pragma once

#include <czr/common.hpp>
#include <czr/rlp/RLP.h>

#include <boost/asio.hpp>

#include <bitset>

#include <xxhash/xxhash.h>

namespace czr
{

	class joint_message
	{
	public:
		joint_message() = default;
		joint_message(std::shared_ptr<czr::block>);
		joint_message(bool & error_a, dev::RLP const & r);
		void stream_RLP(dev::RLPStream & s) const;

		std::shared_ptr<czr::block> block;
		czr::summary_hash summary_hash = 0;
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
		std::list<czr::block_hash> missing_parents_and_previous;
		czr::account account;
		czr::amount amount;
	};

	/**
	* Returns seconds passed since unix epoch (posix time)
	*/
	inline uint64_t seconds_since_epoch()
	{
		return std::chrono::duration_cast<std::chrono::seconds> (std::chrono::system_clock::now().time_since_epoch()).count();
	}

	inline uint64_t future_from_epoch(std::chrono::seconds sec)
	{
		return std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + sec).time_since_epoch()).count();
	}

	bool parse_port(std::string const &, uint16_t &);
}
