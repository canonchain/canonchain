#include "handshake.hpp"

czr::handshake_message::handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, uint256_union const & nonce_a):
	version(version_a),
	network(network_a),
	nonce(nonce_a)
{
}

czr::handshake_message::handshake_message(dev::RLP const & r)
{
	if (r.itemCount() != 3)
		throw std::runtime_error("invalid handshake_message rlp format");

	version = (uint16_t)r[0];
	network = (czr::czr_networks)r[1].toInt<uint8_t>();
	nonce = (czr::uint256_union)r[2];
}

void czr::handshake_message::stream_RLP(dev::RLPStream & s)
{
	s.appendList(3) << version << (uint8_t)network << nonce;
}

czr::ack_message::ack_message(czr::node_id const & node_id_a, czr::signature const & nonce_sig_a, std::list<czr::capability_desc> const & cap_descs_a):
	node_id(node_id_a),
	nonce_sig(nonce_sig_a),
	cap_descs(cap_descs_a)
{
}

czr::ack_message::ack_message(dev::RLP const & r)
{
	if (r.itemCount() != 3)
		throw std::runtime_error("invalid ack_message rlp format");

	node_id = (czr::node_id)r[0];
	nonce_sig = (czr::signature)r[1];
	for (auto const & i : r[2])
		cap_descs.push_back(czr::capability_desc(i));
}

void czr::ack_message::stream_RLP(dev::RLPStream & s)
{
	s.appendList(3) << node_id << nonce_sig;
	s.appendList(cap_descs.size());
	for (auto & desc : cap_descs)
		desc.stream_RLP(s);
}
