#pragma once

#include <czr/lib/numbers.hpp>

#include <assert.h>
#include <blake2/blake2.h>
#include <boost/property_tree/json_parser.hpp>
#include <streambuf>

namespace czr
{
	std::string to_string_hex(uint64_t);
	bool from_string_hex(std::string const &, uint64_t &);
	// We operate on streams of uint8_t by convention
	using stream = std::basic_streambuf<uint8_t>;
	// Read a raw byte stream the size of `T' and fill value.
	template <typename T>
	bool read(czr::stream & stream_a, T & value)
	{
		static_assert (std::is_pod<T>::value, "Can't stream read non-standard layout types");
		auto amount_read(stream_a.sgetn(reinterpret_cast<uint8_t *> (&value), sizeof(value)));
		return amount_read != sizeof(value);
	}
	template <typename T>
	void write(czr::stream & stream_a, T const & value)
	{
		static_assert (std::is_pod<T>::value, "Can't stream write non-standard layout types");
		auto amount_written(stream_a.sputn(reinterpret_cast<uint8_t const *> (&value), sizeof(value)));
		assert(amount_written == sizeof(value));
	}
	class block_visitor;

	class block_hashables
	{
	public:
		block_hashables(czr::account const &, czr::block_hash const &, czr::amount const &, czr::uint256_union const &);
		block_hashables(bool &, czr::stream &);
		block_hashables(bool &, boost::property_tree::ptree const &);
		void hash(blake2b_state &) const;
		// Account# / public key that operates this account
		// Uses:
		// Bulk signature validation in advance of further ledger processing
		// Arranging uncomitted transactions by account
		czr::account account;
		// Previous transaction in this chain
		czr::block_hash previous;
		// Current balance of this account
		// Allows lookup of account balance simply by looking at the head block
		czr::amount balance;
		// Link field contains source block_hash if receiving, destination account if sending
		czr::uint256_union link;

		czr::uint256_union witness_list_block;

		std::vector<czr::account> witness_list;

		czr::uint256_union last_summary_block;

		std::vector<czr::block_hash> parents;

		std::vector<uint8_t> data;
	};

	class block
	{
	public:
		block(czr::account const &, czr::block_hash const &, czr::amount const &, czr::uint256_union const &, czr::raw_key const &, czr::public_key const &, uint64_t);
		block(bool &, czr::stream &);
		block(bool &, boost::property_tree::ptree const &);
		virtual ~block() = default;
		czr::block_hash hash() const;
		std::string to_json();
		uint64_t block_work() const;
		void block_work_set(uint64_t);
		czr::block_hash previous() const;
		czr::block_hash root() const;
		void serialize(czr::stream &) const;
		void serialize_json(std::string &) const;
		bool deserialize(czr::stream &);
		bool deserialize_json(boost::property_tree::ptree const &);
		void visit(czr::block_visitor &) const;
		czr::signature block_signature() const;
		void signature_set(czr::uint512_union const &);
		bool operator== (czr::block const &) const;
		//todo:remove size/////////////////////
		static size_t constexpr size = sizeof(czr::account) + sizeof(czr::block_hash) + sizeof(czr::account) + sizeof(czr::amount) + sizeof(czr::uint256_union) + sizeof(czr::signature) + sizeof(uint64_t);
		czr::block_hashables hashables;
		czr::signature signature;
		uint64_t work; // Only least 48 least significant bits are encoded
	};

	class block_visitor
	{
	public:
		virtual void block(czr::block const &) = 0;
		virtual ~block_visitor() = default;
	};

	std::unique_ptr<czr::block> deserialize_block(czr::stream &);
	std::unique_ptr<czr::block> deserialize_block_json(boost::property_tree::ptree const &);
}
