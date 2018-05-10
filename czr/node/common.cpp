
#include <czr/node/common.hpp>

#include <czr/lib/work.hpp>
#include <czr/node/wallet.hpp>

std::array<uint8_t, 2> constexpr czr::message::magic_number;
size_t constexpr czr::message::ipv4_only_position;
size_t constexpr czr::message::bootstrap_server_position;

czr::message::message (czr::message_type type_a) :
version_max (0x07),
version_using (0x07),
version_min (0x01),
type (type_a)
{
}

czr::message::message (bool & error_a, czr::stream & stream_a)
{
	error_a = read_header (stream_a, version_max, version_using, version_min, type, extensions);
}

bool czr::message::ipv4_only ()
{
	return extensions.test (ipv4_only_position);
}

void czr::message::ipv4_only_set (bool value_a)
{
	extensions.set (ipv4_only_position, value_a);
}

void czr::message::write_header (czr::stream & stream_a)
{
	czr::write (stream_a, czr::message::magic_number);
	czr::write (stream_a, version_max);
	czr::write (stream_a, version_using);
	czr::write (stream_a, version_min);
	czr::write (stream_a, type);
	czr::write (stream_a, static_cast<uint16_t> (extensions.to_ullong ()));
}

bool czr::message::read_header (czr::stream & stream_a, uint8_t & version_max_a, uint8_t & version_using_a, uint8_t & version_min_a, czr::message_type & type_a, std::bitset<16> & extensions_a)
{
	uint16_t extensions_l;
	std::array<uint8_t, 2> magic_number_l;
	auto result (czr::read (stream_a, magic_number_l));
	result = result || magic_number_l != magic_number;
	result = result || czr::read (stream_a, version_max_a);
	result = result || czr::read (stream_a, version_using_a);
	result = result || czr::read (stream_a, version_min_a);
	result = result || czr::read (stream_a, type_a);
	result = result || czr::read (stream_a, extensions_l);
	if (!result)
	{
		extensions_a = extensions_l;
	}
	return result;
}

czr::message_parser::message_parser (czr::message_visitor & visitor_a, czr::work_pool & pool_a) :
visitor (visitor_a),
pool (pool_a),
status (parse_status::success)
{
}

void czr::message_parser::deserialize_buffer (uint8_t const * buffer_a, size_t size_a)
{
	status = parse_status::success;
	czr::bufferstream header_stream (buffer_a, size_a);
	uint8_t version_max;
	uint8_t version_using;
	uint8_t version_min;
	czr::message_type type;
	std::bitset<16> extensions;
	if (!czr::message::read_header (header_stream, version_max, version_using, version_min, type, extensions))
	{
		switch (type)
		{
			case czr::message_type::keepalive:
			{
				deserialize_keepalive (buffer_a, size_a);
				break;
			}
			case czr::message_type::publish:
			{
				deserialize_publish (buffer_a, size_a);
				break;
			}
			default:
			{
				status = parse_status::invalid_message_type;
				break;
			}
		}
	}
	else
	{
		status = parse_status::invalid_header;
	}
}

void czr::message_parser::deserialize_keepalive (uint8_t const * buffer_a, size_t size_a)
{
	czr::keepalive incoming;
	czr::bufferstream stream (buffer_a, size_a);
	auto error_l (incoming.deserialize (stream));
	if (!error_l && at_end (stream))
	{
		visitor.keepalive (incoming);
	}
	else
	{
		status = parse_status::invalid_keepalive_message;
	}
}

void czr::message_parser::deserialize_publish (uint8_t const * buffer_a, size_t size_a)
{
	czr::publish incoming;
	czr::bufferstream stream (buffer_a, size_a);
	auto error_l (incoming.deserialize (stream));
	if (!error_l && at_end (stream))
	{
		if (!czr::work_validate (*incoming.block))
		{
			visitor.publish (incoming);
		}
		else
		{
			status = parse_status::insufficient_work;
		}
	}
	else
	{
		status = parse_status::invalid_publish_message;
	}
}

bool czr::message_parser::at_end (czr::bufferstream & stream_a)
{
	uint8_t junk;
	auto end (czr::read (stream_a, junk));
	return end;
}

czr::keepalive::keepalive () :
message (czr::message_type::keepalive)
{
	czr::endpoint endpoint (boost::asio::ip::address_v6{}, 0);
	for (auto i (peers.begin ()), n (peers.end ()); i != n; ++i)
	{
		*i = endpoint;
	}
}

void czr::keepalive::visit (czr::message_visitor & visitor_a) const
{
	visitor_a.keepalive (*this);
}

void czr::keepalive::serialize (czr::stream & stream_a)
{
	write_header (stream_a);
	for (auto i (peers.begin ()), j (peers.end ()); i != j; ++i)
	{
		assert (i->address ().is_v6 ());
		auto bytes (i->address ().to_v6 ().to_bytes ());
		write (stream_a, bytes);
		write (stream_a, i->port ());
	}
}

bool czr::keepalive::deserialize (czr::stream & stream_a)
{
	auto error (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!error);
	assert (type == czr::message_type::keepalive);
	for (auto i (peers.begin ()), j (peers.end ()); i != j && !error; ++i)
	{
		std::array<uint8_t, 16> address;
		uint16_t port;
		if (!read (stream_a, address) && !read (stream_a, port))
		{
			*i = czr::endpoint (boost::asio::ip::address_v6 (address), port);
		}
		else
		{
			error = true;
		}
	}
	return error;
}

bool czr::keepalive::operator== (czr::keepalive const & other_a) const
{
	return peers == other_a.peers;
}

czr::publish::publish () :
message (czr::message_type::publish)
{
}

czr::publish::publish (std::shared_ptr<czr::block> block_a) :
message (czr::message_type::publish),
block (block_a)
{
}

bool czr::publish::deserialize (czr::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (type == czr::message_type::publish);
	if (!result)
	{
		block = czr::deserialize_block (stream_a);
		result = block == nullptr;
	}
	return result;
}

void czr::publish::serialize (czr::stream & stream_a)
{
	assert (block != nullptr);
	write_header (stream_a);
	block->serialize (stream_a);
}

void czr::publish::visit (czr::message_visitor & visitor_a) const
{
	visitor_a.publish (*this);
}

bool czr::publish::operator== (czr::publish const & other_a) const
{
	return *block == *other_a.block;
}

czr::message_visitor::~message_visitor ()
{
}
