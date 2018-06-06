#include "frame_coder.hpp"


czr::frame_coder::frame_coder()
{
}

void czr::frame_coder::write_frame(dev::bytesConstRef packet, dev::bytes & frame_bytes)
{
	uint32_t packet_size(packet.size());
	dev::bytes header(serialize_packet_size(packet_size));
	frame_bytes.swap(header);
	frame_bytes.resize(4 + packet_size);
	dev::bytesRef packetRef(frame_bytes.data() + 4, packet_size);
	packet.copyTo(packetRef);
}

std::vector<uint8_t> czr::frame_coder::serialize_packet_size(uint32_t const & size)
{
	std::vector<uint8_t> data(czr::message_header_size);
	data[0] = (size >> 24) & 0xff;
	data[1] = (size >> 16) & 0xff;
	data[2] = (size >> 8) & 0xff;
	data[3] = size & 0xff;
	return data;
}

uint32_t czr::frame_coder::deserialize_packet_size(std::vector<uint8_t> const & data)
{
	uint32_t size(data[0] << 24 + data[1] << 16 + data[2] << 8 + data[3]);
	return size;
}
