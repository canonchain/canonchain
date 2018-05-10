#include <czr/lib/blocks.hpp>

#include <boost/endian/conversion.hpp>

std::string czr::to_string_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool czr::from_string_hex (std::string const & value_a, uint64_t & target_a)
{
	auto error (value_a.empty ());
	if (!error)
	{
		error = value_a.size () > 16;
		if (!error)
		{
			std::stringstream stream (value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof ())
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

std::string czr::block::to_json ()
{
	std::string result;
	serialize_json (result);
	return result;
}

czr::block_hash czr::block::hash () const
{
	czr::uint256_union result;
	blake2b_state hash_l;
	auto status (blake2b_init (&hash_l, sizeof (result.bytes)));
	assert (status == 0);

	hashables.hash(hash_l);

	status = blake2b_final (&hash_l, result.bytes.data (), sizeof (result.bytes));
	assert (status == 0);
	return result;
}

czr::block_hashables::block_hashables(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, 
	czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a, 
	czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
	czr::summary_hash const & last_summary_a, czr::block_hash const & last_summary_block_a,
	std::vector<uint8_t> const & data_a):
from(from_a),
to(to_a),
amount (amount_a),
previous(previous_a),
parents(parents_a),
witness_list_block(witness_list_block_a),
witness_list(witness_list_a),
last_summary(last_summary_a),
last_summary_block(last_summary_block_a),
data(data_a)
{
	//todo:need fee feild ???
}

czr::block_hashables::block_hashables (bool & error_a, czr::stream & stream_a)
{
	//todo: add new feilds /////////////////
	error_a = czr::read(stream_a, from);
	if (!error_a)
	{
		error_a = czr::read(stream_a, to);
		if (!error_a)
		{
			error_a = czr::read(stream_a, amount);
		}
	}
}

czr::block_hashables::block_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	deserialize_json(error_a, tree_a);
}

void czr::block_hashables::serialize_json(boost::property_tree::ptree tree_a, std::string & string_a) const
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

	std::string data_str;	//todo:serialize data to string
	tree_a.put("data", data_str);
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

		//todo:derialize dat from string to bytes;
		auto data_l(tree_a.get<std::string>("data"));
		//error_a = data.derialize(data_l) 
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

	blake2b_update(&hash_a, data.data(), sizeof(data));
}

czr::block::block(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a, 
	czr::block_hash const & previous_a, std::vector<czr::block_hash> const & parents_a, 
	czr::block_hash const & witness_list_block_a, std::vector<czr::account> const & witness_list_a,
	czr::summary_hash const & last_summary_a, czr::block_hash const & last_summary_block_a,
	std::vector<uint8_t> const & data_a,
	czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t work_a):
hashables(from_a, to_a, amount_a, previous_a, parents_a, witness_list_block_a, witness_list_a, last_summary_a, last_summary_block_a, data_a),
signature(czr::sign_message(prv_a, pub_a, hash())),
work(work_a)
{
}

czr::block::block (bool & error_a, czr::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = czr::read (stream_a, signature);
		if (!error_a)
		{
			error_a = czr::read (stream_a, work);
			boost::endian::big_to_native_inplace (work);
		}
	}
}

czr::block::block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l(tree_a.get<std::string>("work"));
			error_a = czr::from_string_hex(work_l, work);
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
}

uint64_t czr::block::block_work () const
{
	return work;
}

void czr::block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

czr::block_hash czr::block::previous () const
{
	return hashables.previous;
}

std::vector<czr::block_hash> czr::block::parents_and_previous() const
{
	std::vector<czr::block_hash> list(hashables.parents);
	if (!hashables.previous.is_zero() && std::find(list.begin(), list.end(), hashables.previous) == list.end())
		list.push_back(hashables.previous);

	return list;
}

void czr::block::serialize (czr::stream & stream_a) const
{
	//todo:serialize block///////////////
	write (stream_a, hashables.from);
	write (stream_a, hashables.to);
	write (stream_a, hashables.amount);
	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
}

bool czr::block::deserialize (czr::stream & stream_a)
{
	//todo:deserialize block///////////////
	auto error = read(stream_a, hashables.from);
	if (!error)
	{
		error = read(stream_a, hashables.to);
		if (!error)
		{
			error = read(stream_a, hashables.amount);
			if (!error)
			{
				error = read(stream_a, signature);
				if (!error)
				{
					error = read(stream_a, work);
					boost::endian::big_to_native_inplace(work);
				}
			}
		}
	}
	return error;
}

void czr::block::serialize_json(std::string & string_a) const
{
	boost::property_tree::ptree tree;

	hashables.serialize_json(tree, string_a);

	std::string signature_l;
	signature.encode_hex(signature_l);
	tree.put("signature", signature_l);
	tree.put("work", czr::to_string_hex(work));
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

		auto work_l (tree_a.get<std::string> ("work"));
		error_a = czr::from_string_hex(work_l, work);
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

void czr::block::visit (czr::block_visitor & visitor_a) const
{
	visitor_a.block (*this);
}

bool czr::block::operator== (czr::block const & other_a) const
{
	return hash() == other_a.hash()
		&& signature == other_a.signature 
		&& work == other_a.work;
}

czr::block_hash czr::block::root () const
{
	return !previous().is_zero () ? previous() : hashables.from;
}

czr::signature czr::block::block_signature () const
{
	return signature;
}

void czr::block::signature_set (czr::uint512_union const & signature_a)
{
	signature = signature_a;
}

std::unique_ptr<czr::block> czr::deserialize_block_json (boost::property_tree::ptree const & tree_a)
{
	std::unique_ptr<czr::block> result;
	try
	{
		bool error;
		std::unique_ptr<czr::block> obj(new czr::block(error, tree_a));
		if (!error)
		{
			result = std::move(obj);
		}
	}
	catch (std::runtime_error const &)
	{
	}
	return result;
}

std::unique_ptr<czr::block> czr::deserialize_block (czr::stream & stream_a)
{
	std::unique_ptr<czr::block> result;
	bool error;
	std::unique_ptr<czr::block> obj(new czr::block(error, stream_a));
	if (!error)
		result = std::move(obj);

	return result;
}
