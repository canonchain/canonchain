#include <czr/lib/blocks.hpp>


std::string czr::uint64_to_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool czr::hex_to_uint64(std::string const & value_a, uint64_t & target_a)
{
	auto error(value_a.empty());
	if (!error)
	{
		error = value_a.size() > 16;
		if (!error)
		{
			std::stringstream stream(value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof())
				{
					error = true;
				}
			}
			catch (std::runtime_error &)
			{
				error = true;
			}
		}
	}
	return error;
}

std::string czr::bytes_to_hex(dev::bytes const & b)
{
	static char const* hexdigits = "0123456789abcdef";
	std::string hex(b.size() * 2, '0');
	int off = 0;
	for (auto it(b.begin()); it != b.end(); it++)
	{
		hex[off++] = hexdigits[(*it >> 4) & 0x0f];
		hex[off++] = hexdigits[*it & 0x0f];
	}
	return hex;
}

int czr::from_hex_char(char c) noexcept
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

bool czr::hex_to_bytes(std::string const & str , dev::bytes & out)
{
	bool error(str.size() % 2 != 0);
	if (error)
		return error;

	unsigned s = (str.size() >= 2 && str[0] == '0' && str[1] == 'x') ? 2 : 0;
	out.reserve((str.size() - s + 1) / 2);
	for (unsigned i = s; i < str.size(); i += 2)
	{
		int h = from_hex_char(str[i]);
		int l = from_hex_char(str[i + 1]);
		if (h != -1 && l != -1)
			out.push_back((byte)(h * 16 + l));
		else
		{
			error = true;
			break;
		}
	}
	return error;
}

czr::block_hashables::block_hashables(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, 
	czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a, 
	czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
	czr::summary_hash const & last_summary_a, czr::block_hash const & last_summary_block_a,
	std::vector<uint8_t> const & data_a, uint64_t const & exec_timestamp_a):
from(from_a),
to(to_a),
amount (amount_a),
previous(previous_a),
parents(parents_a),
witness_list_block(witness_list_block_a),
witness_list(witness_list_a),
last_summary(last_summary_a),
last_summary_block(last_summary_block_a),
data(data_a),
exec_timestamp(exec_timestamp_a)
{
	//todo:need fee feild ???
}

czr::block_hashables::block_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	deserialize_json(error_a, tree_a);
}

czr::block_hashables::block_hashables(bool & error_a, dev::RLP const & r)
{
	error_a = r.itemCount() != 10;
	from = (czr::account)r[0];
	to = (czr::account)r[1];
	amount = (czr::amount)r[2];
	previous = (czr::block_hash)r[3];

	dev::RLP const & parents_rlp = r[4];
	parents.resize(parents_rlp.itemCount());
	for (dev::RLP const &  parent : parents_rlp)
	{
		parents.push_back((czr::block_hash)parent);
	}

	dev::RLP const & witness_rlp = r[5];
	if (!witness_rlp.isList())
	{
		witness_list_block = (czr::block_hash)witness_rlp;
	}
	else
	{
		witness_list.resize(witness_rlp.itemCount());
		for (dev::RLP const & witness : witness_rlp)
			witness_list.push_back((czr::block_hash)witness);
	}

	last_summary = (czr::summary_hash)r[6];
	last_summary_block = (czr::block_hash)r[7];
	data = r[8].toBytes();
	exec_timestamp = (uint64_t)r[9];
}

void czr::block_hashables::stream_RLP(dev::RLPStream & s) const
{
	s.appendList(10);
	s << from << to << amount << previous;

	s.appendList(parents.size());
	for (czr::block_hash const & parent : parents)
		s << parent;

	if (!witness_list_block.is_zero())
	{
		s << witness_list_block;
	}
	else
	{
		s.appendList(witness_list.size());
		for (czr::account witness : witness_list)
			s << witness;
	}

	s << last_summary << last_summary_block << data << exec_timestamp;
}

void czr::block_hashables::serialize_json(boost::property_tree::ptree tree_a) const
{
	tree_a.put("from", from.to_account());
	tree_a.put("to", to.to_account());
	tree_a.put("amount", amount.to_string_dec());
	tree_a.put("previous", previous.to_string());

	boost::property_tree::ptree parents_tree;
	for (czr::block_hash p : parents)
		parents_tree.put("", p.to_string());
	tree_a.put_child("parents", parents_tree);

	tree_a.put("witness_list_block", witness_list_block.to_string());

	boost::property_tree::ptree witness_list_tree;
	for (czr::account w : witness_list)
		witness_list_tree.put("", w.to_account());
	tree_a.put_child("witness_list", witness_list_tree);

	tree_a.put("last_summary", last_summary.to_string());
	tree_a.put("last_summary_block", last_summary_block.to_string());

	std::string data_str(czr::bytes_to_hex(data));
	tree_a.put("data", data_str);

	tree_a.put("exec_timestamp", exec_timestamp);
}

void czr::block_hashables::deserialize_json(bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto from_l(tree_a.get<std::string>("from"));
		error_a = from.decode_account(from_l);
		if (error_a)
			return;

		auto to_l(tree_a.get<std::string>("to"));
		error_a = to.decode_account(to_l);
		if (error_a)
			return;

		auto amount_l(tree_a.get<std::string>("amount"));
		error_a = amount.decode_dec(amount_l);
		if (error_a)
			return;

		auto previous_l(tree_a.get<std::string>("previous"));
		error_a = previous.decode_hex(previous_l);
		if (error_a)
			return;

		auto parents_l(tree_a.get_child("parents"));
		for (auto p : parents_l)
		{
			czr::block_hash parent;
			error_a = parent.decode_hex(p.second.data());
			if (error_a)
				break;
			parents.push_back(parent);
		}
		if (error_a)
			return;

		auto witness_list_block_l(tree_a.get<std::string>("witness_list_block"));
		error_a = witness_list_block.decode_hex(witness_list_block_l);
		if (error_a)
			return;

		auto witness_list_l(tree_a.get_child("witness_list"));
		for (auto w : witness_list_l)
		{
			czr::account witness;
			error_a = witness.decode_account(w.second.data());
			if (error_a)
				break;
			witness_list.push_back(witness);
		}

		if (error_a)
			return;

		auto last_summary_l(tree_a.get<std::string>("last_summary"));
		error_a = last_summary.decode_hex(last_summary_l);
		if (error_a)
			return;

		auto last_summary_block_l(tree_a.get<std::string>("last_summary_block"));
		error_a = last_summary_block.decode_hex(last_summary_block_l);
		if (error_a)
			return;

		auto data_l(tree_a.get<std::string>("data"));
		error_a = czr::hex_to_bytes(data_l, data);
		if (error_a)
			return;

		auto exec_timestamp_l(tree_a.get<std::string>("exec_timestamp"));
		std::stringstream exec_timestamp_ss(exec_timestamp_l);
		error_a = (exec_timestamp_ss >> exec_timestamp).bad();
		if (error_a)
			return;
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void czr::block_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update(&hash_a, from.bytes.data(), sizeof(from.bytes));
	blake2b_update(&hash_a, to.bytes.data(), sizeof(to.bytes));
	blake2b_update(&hash_a, amount.bytes.data(), sizeof(amount.bytes));
	blake2b_update(&hash_a, previous.bytes.data(), sizeof(previous.bytes));
	for (auto p : parents)
		blake2b_update(&hash_a, p.bytes.data(), sizeof(p.bytes));

	if(witness_list.empty())
		blake2b_update(&hash_a, witness_list_block.bytes.data(), sizeof(witness_list_block.bytes));
	else
	{
		for (auto witness : witness_list)
			blake2b_update(&hash_a, witness.bytes.data(), sizeof(witness.bytes));
	}

	blake2b_update(&hash_a, last_summary.bytes.data(), sizeof(last_summary.bytes));
	blake2b_update(&hash_a, last_summary_block.bytes.data(), sizeof(last_summary_block.bytes));
	
	if(data.size() > 0)
		blake2b_update(&hash_a, &data[0], data.size());
	blake2b_update(&hash_a, &exec_timestamp, sizeof(exec_timestamp));
}

czr::block::block(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, 
	czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a, 
	czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
	czr::summary_hash const & last_summary_a, czr::block_hash const & last_summary_block_a,
	std::vector<uint8_t> const & data_a, uint64_t const & exec_timestamp_a,
	czr::raw_key const & prv_a, czr::public_key const & pub_a):
hashables(from_a, to_a, amount_a, previous_a, parents_a, witness_list_block_a, witness_list_a, last_summary_a, last_summary_block_a, data_a, exec_timestamp_a),
signature(czr::sign_message(prv_a, pub_a, hash()))
{
}

czr::block::block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l(tree_a.get<std::string>("signature"));
			error_a = signature.decode_hex(signature_l);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

czr::block::block(bool & error_a, dev::RLP const & r):
	hashables(error_a, r[0])
{
	error_a = r.itemCount() != 2;
	if (error_a)
		return;

	signature = (czr::signature)r[1];
}

void czr::block::stream_RLP(dev::RLPStream & s) const
{
	s.appendList(2);
	hashables.stream_RLP(s);
	s << signature;
}

czr::block_hash czr::block::previous () const
{
	return hashables.previous;
}

std::vector<czr::block_hash> czr::block::parents() const
{
	return hashables.parents;
}

std::vector<czr::block_hash> czr::block::parents_and_previous() const
{
	std::vector<czr::block_hash> list(hashables.parents);
	if (!hashables.previous.is_zero() && std::find(list.begin(), list.end(), hashables.previous) == list.end())
		list.push_back(hashables.previous);

	return list;
}

void czr::block::serialize_json(std::string & string_a) const
{
	boost::property_tree::ptree tree;

	hashables.serialize_json(tree);

	std::string signature_l;
	signature.encode_hex(signature_l);
	tree.put("signature", signature_l);

	std::stringstream ostream;
	boost::property_tree::write_json(ostream, tree);
	string_a = ostream.str();
}

void czr::block::deserialize_json (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		hashables.deserialize_json(error_a, tree_a);
		if (error_a)
			return;

		auto signature_l(tree_a.get<std::string>("signature"));
		error_a = signature.decode_hex(signature_l);

	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

std::string czr::block::to_json()
{
	std::string result;
	serialize_json(result);
	return result;
}

czr::block_hash czr::block::hash() const
{
	czr::uint256_union result;
	blake2b_state hash_l;
	auto status(blake2b_init(&hash_l, sizeof(result.bytes)));
	assert(status == 0);

	hashables.hash(hash_l);

	status = blake2b_final(&hash_l, result.bytes.data(), sizeof(result.bytes));
	assert(status == 0);
	return result;
}

void czr::block::visit (czr::block_visitor & visitor_a) const
{
	visitor_a.block (*this);
}

bool czr::block::operator== (czr::block const & other_a) const
{
	return hash() == other_a.hash()
		&& signature == other_a.signature;
}

czr::block_hash czr::block::root () const
{
	return !previous().is_zero () ? previous() : hashables.from;
}

czr::signature czr::block::block_signature () const
{
	return signature;
}

std::unique_ptr<czr::block> czr::interpret_block_RLP (dev::RLP const & r)
{
	std::unique_ptr<czr::block> result;
	bool error;
	std::unique_ptr<czr::block> obj(new czr::block(error, r));
	if (!error)
		result = std::move(obj);

	return result;
}
