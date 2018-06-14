#pragma once

#include <czr/p2p/common.hpp>

namespace czr
{
	class frame_coder
	{
	public:
		frame_coder();

		void write_frame(dev::bytesConstRef _packet, dev::bytes & frame_bytes);
		std::vector<uint8_t> serialize_packet_size(uint32_t const & size);
		uint32_t deserialize_packet_size(std::vector<uint8_t> const & data);
	};
}