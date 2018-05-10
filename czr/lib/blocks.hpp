#pragma once

#include <czr/lib/numbers.hpp>

#include <assert.h>
#include <blake2/blake2.h>
#include <boost/property_tree/json_parser.hpp>
#include <streambuf>

namespace czr
{
std::string to_string_hex (uint64_t);
bool from_string_hex (std::string const &, uint64_t &);
// We operate on streams of uint8_t by convention
using stream = std::basic_streambuf<uint8_t>;
// Read a raw byte stream the size of `T' and fill value.
template <typename T>
bool read (czr::stream & stream_a, T & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream read non-standard layout types");
	auto amount_read (stream_a.sgetn (reinterpret_cast<uint8_t *> (&value), sizeof (value)));
	return amount_read != sizeof (value);
}
template <typename T>
void write (czr::stream & stream_a, T const & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream write non-standard layout types");
	auto amount_written (stream_a.sputn (reinterpret_cast<uint8_t const *> (&value), sizeof (value)));
	assert (amount_written == sizeof (value));
}
class block_visitor;

class block_hashables
{
public:
	block_hashables (czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a,
		czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a,
		czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
		czr::summary_hash const & last_summary_a, czr::block_hash const & last_summary_block_a,
		std::vector<uint8_t> const & data_a);
	block_hashables (bool &, czr::stream &);
	block_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;

	czr::account from;
	czr::account to;
	czr::amount amount;
	czr::block_hash previous;
	std::vector<czr::block_hash> parents;
	czr::block_hash witness_list_block;
	std::vector<czr::account> witness_list;
	czr::summary_hash last_summary;
	czr::block_hash last_summary_block;
	std::vector<uint8_t> data;
};

class block
{
public:
	block(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, 
		czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a,
		czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
		czr::summary_hash const & last_summary_a,	czr::block_hash const & last_summary_block_a,
		std::vector<uint8_t> const & data_a,
		czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t work_a);
	block(bool &, czr::stream &);
	block(bool &, boost::property_tree::ptree const &);
	virtual ~block() = default;
	czr::block_hash hash() const;
	std::string to_json();
	uint64_t block_work() const;
	void block_work_set(uint64_t);
	czr::block_hash previous() const;
	std::vector<czr::block_hash> parents_and_previous() const;
	czr::block_hash root() const;
	void serialize(czr::stream &) const;
	void serialize_json(std::string &) const;
	bool deserialize(czr::stream &);
	bool deserialize_json(boost::property_tree::ptree const &);
	void visit(czr::block_visitor &) const;
	czr::signature block_signature() const;
	void signature_set(czr::uint512_union const &);
	bool operator== (czr::block const &) const;
	czr::block_hashables hashables;
	czr::signature signature;
	uint64_t work; // Only least 48 least significant bits are encoded
};

class block_visitor
{
public:
	virtual void block (czr::block const &) = 0;
	virtual ~block_visitor () = default;
};

std::unique_ptr<czr::block> deserialize_block (czr::stream &);
std::unique_ptr<czr::block> deserialize_block_json (boost::property_tree::ptree const &);
}
