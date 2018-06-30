#include <czr/node/wallet.hpp>

#include <czr/node/node.hpp>
#include <czr/node/composer.hpp>

#include <argon2.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <future>

#include <ed25519-donna/ed25519.h>

void czr::kdf::phs(czr::raw_key & result_a, std::string const & password_a, czr::uint256_union const & salt_a)
{
	std::lock_guard<std::mutex> lock(mutex);
	auto success(argon2_hash(1, kdf_work, 1, password_a.data(), password_a.size(), salt_a.bytes.data(), salt_a.bytes.size(), result_a.data.bytes.data(), result_a.data.bytes.size(), NULL, 0, Argon2_d, 0x10));
	assert(success == 0);
	(void)success;
}


czr::wallet::wallet(bool & error_a, czr::node & node_a) :
	node(node_a),
	stopped(false),
	composer(std::make_shared<czr::composer>(node_a)),
	thread([this]() { do_wallet_actions(); })
{
	if (!error_a)
	{
		czr::transaction transaction(node.store.environment, nullptr, true);
		auto status(mdb_dbi_open(transaction, "send_action_ids", MDB_CREATE, &send_action_ids));
		assert(status == 0);
	}
}

czr::wallet::~wallet()
{
	stop();
	thread.join();
}

void czr::wallet::send_async(czr::account const & from_a, czr::account const & to_a, czr::amount const & amount_a,
	std::vector<uint8_t> const & data_a, std::string const & password_a, std::function<void(czr::send_result)> const & action_a,
	boost::optional<std::string> id_a)
{
	node.background([this, from_a, to_a, amount_a, data_a, action_a, password_a, id_a]() {
		this->queue_wallet_action([this, from_a, to_a, amount_a, data_a, action_a, password_a, id_a]() {
			auto result(send_action(from_a, to_a, amount_a, data_a, password_a, id_a));
			action_a(result);
		});
	});
}

czr::send_result czr::wallet::send_action(czr::account const & from_a, czr::account const & to_a,
	czr::amount const & amount_a, std::vector<uint8_t> data_a, std::string const & password_a, boost::optional<std::string> id_a)
{
	std::shared_ptr<czr::joint_message> joint;
	boost::optional<czr::mdb_val> id_mdb_val;
	if (id_a)
	{
		id_mdb_val = czr::mdb_val(id_a->size(), const_cast<char *> (id_a->data()));
	}
	bool error = false;
	bool cached_block = false;
	{
		if (id_mdb_val)
		{
			czr::transaction transaction(node.store.environment, nullptr, false);
			czr::mdb_val result;
			auto status(mdb_get(transaction, send_action_ids, *id_mdb_val, result));
			if (status == 0)
			{
				auto hash(result.uint256());
				auto block = node.store.block_get(transaction, hash);
				if (block != nullptr)
				{
					joint = std::make_shared<czr::joint_message>(std::shared_ptr<czr::block>(block.release()));
					cached_block = true;
				}
			}
			else if (status != MDB_NOTFOUND)
			{
				error = true;
			}
		}
		if (!error && joint == nullptr)
		{
			{
				czr::transaction transaction(node.store.environment, nullptr, false);

				bool exists(node.key_manager.exists(from_a));
				if (!exists)
				{
					return czr::send_result(czr::send_result_codes::from_not_exists, nullptr);
				}

				czr::raw_key prv;
				if (password_a.empty())
				{
					bool exists(node.key_manager.find_unlocked_prv(from_a, prv));
					if (!exists)
						return czr::send_result(czr::send_result_codes::account_locked, nullptr);
				}
				else
				{
					bool error(node.key_manager.decrypt_prv(from_a, password_a, prv));
					if (error)
						return czr::send_result(czr::send_result_codes::wrong_password, nullptr);
				}

				czr::compose_result compose_result(composer->compose(transaction, from_a, to_a, amount_a, data_a, prv, from_a));
				switch (compose_result.code)
				{
				case czr::compose_result_codes::ok:
					joint = compose_result.message;
					break;
				case czr::compose_result_codes::insufficient_balance:
					return czr::send_result(czr::send_result_codes::insufficient_balance, nullptr);
				case czr::compose_result_codes::data_size_too_large:
					return czr::send_result(czr::send_result_codes::data_size_too_large, nullptr);
				case czr::compose_result_codes::validate_error:
					return czr::send_result(czr::send_result_codes::validate_error, nullptr);
				case czr::compose_result_codes::error:
					error = true;
					break;
				default:
					BOOST_LOG(node.log) << "invalid compose result codes";
					return czr::send_result(czr::send_result_codes::error, nullptr);
				}
			}

			if (joint != nullptr)
			{
				if (id_mdb_val)
				{
					czr::transaction transaction(node.store.environment, nullptr, true);
					auto status(mdb_put(transaction, node.wallet.send_action_ids, *id_mdb_val, czr::mdb_val(joint->block->hash()), 0));
					if (status != 0)
					{
						joint = nullptr;
						error = true;
					}
				}
			}
		}
	}
	if (!error && joint != nullptr)
	{
		node.process_local_joint(*joint);
	}

	if (error)
	{
		return czr::send_result(czr::send_result_codes::error, nullptr);
	}
	else
	{
		return czr::send_result(czr::send_result_codes::ok, joint->block);
	}
}

void czr::wallet::do_wallet_actions()
{
	std::unique_lock<std::mutex> lock(mutex);
	while (!stopped)
	{
		if (!actions.empty())
		{
			auto first(actions.front());
			auto current(std::move(first));
			actions.pop_front();
			lock.unlock();
			current();
			lock.lock();
		}
		else
		{
			condition.wait(lock);
		}
	}
}

void czr::wallet::queue_wallet_action(std::function<void()> const & action_a)
{
	std::lock_guard<std::mutex> lock(mutex);
	actions.push_back(std::move(action_a));
	condition.notify_all();
}

void czr::wallet::stop()
{
	std::lock_guard<std::mutex> lock(mutex);
	stopped = true;
	condition.notify_all();
}


czr::send_result::send_result(czr::send_result_codes const & code_a, std::shared_ptr<czr::block> block_a):
	code(code_a),
	block(block_a)
{
}


czr::key_content::key_content()
{
}

czr::key_content::key_content(MDB_val const & val_a)
{
	assert(val_a.mv_size == sizeof(*this));
	std::copy(reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof(*this), reinterpret_cast<uint8_t *> (this));
}

czr::key_content::key_content(bool & error_a, std::string const & json_a)
{
	boost::property_tree::ptree p;
	std::stringstream istream(json_a);
	try
	{
		boost::property_tree::read_json(istream, p);

		if (!error_a)
		{
			std::string account_text(p.get<std::string>("account"));
			error_a = account.decode_account(account_text);

			if (!error_a)
			{
				std::string kdf_salt_text(p.get<std::string>("kdf_salt"));
				error_a = kdf_salt.decode_hex(kdf_salt_text);

				if (!error_a)
				{
					std::string iv_text(p.get<std::string>("iv"));
					error_a = iv.decode_hex(iv_text);

					if (!error_a)
					{
						std::string ciphertext_text(p.get<std::string>("ciphertext"));
						error_a = ciphertext.decode_hex(ciphertext_text);
					}
				}
			}
		}
	}
	catch (std::exception const &e)
	{
		error_a = true;
	}
}

czr::key_content::key_content(czr::account const & account_a, czr::uint256_union const & kdf_salt_a, 
	czr::uint128_union const & iv_a, czr::secret_key const & ciphertext_a):
	account(account_a),
	kdf_salt(kdf_salt_a),
	iv(iv_a),
	ciphertext(ciphertext_a)
{
}

czr::mdb_val czr::key_content::val() const
{
	return czr::mdb_val(sizeof(*this), const_cast<czr::key_content *> (this));
}

std::string czr::key_content::to_json() const
{
	boost::property_tree::ptree p;

	p.put("account", account.to_account());
	p.put("kdf_salt", kdf_salt.to_string());
	p.put("iv", iv.to_string());
	p.put("ciphertext", ciphertext.to_string());

	std::stringstream ostream;
	boost::property_tree::write_json(ostream, p, false);
	return ostream.str();
}

czr::key_manager::key_manager(bool & error_a, czr::mdb_env & environment, boost::filesystem::path const & application_path_a):
	backup_path(application_path_a / "backup")
{
	if (!error_a)
	{
		czr::transaction transaction(environment, nullptr, true);
		auto error(0);
		error |= mdb_dbi_open(transaction, "keys", MDB_CREATE, &keys);
		error_a = error != 0;
		if (!error_a)
		{
			for (czr::store_iterator i(transaction, keys), n(nullptr); i != n; ++i)
			{
				czr::public_key pub(i->first.uint256());
				czr::key_content key_content(i->second);
				key_contents[pub] = key_content;
			}
		}
		if (!error_a)
			 boost::filesystem::create_directories(backup_path);
	}
}

bool czr::key_manager::exists(czr::public_key const & pub_a)
{
	std::lock_guard<std::mutex> lock(key_contents_mutex);
	return key_contents.count(pub_a) > 0;
}

bool czr::key_manager::find(czr::public_key const & pub_a, czr::key_content & kc_a)
{
	bool exists(true);
	std::lock_guard<std::mutex> lock(key_contents_mutex);
	if (key_contents.count(pub_a))
	{
		kc_a = key_contents[pub_a];
	}
	else
	{
		exists = false;
	}
	return exists;
}

std::list<czr::public_key> czr::key_manager::list()
{
	std::list<czr::public_key> pubs;
	std::lock_guard<std::mutex> lock(key_contents_mutex);
	for (auto pair : key_contents)
		pubs.push_back(pair.first);
	return pubs;
}

czr::public_key czr::key_manager::create(MDB_txn * transaction_a, std::string const & password_a)
{
	czr::raw_key prv;
	random_pool.GenerateBlock(prv.data.bytes.data(), prv.data.bytes.size());

	czr::key_content kc(gen_key_content(prv, password_a));
	add_or_update_key(transaction_a, kc);

	return kc.account;
}

bool czr::key_manager::change_password(MDB_txn * transaction_a, czr::public_key const & pub_a,
	std::string const & old_password_a, std::string const & new_password_a)
{
	czr::raw_key prv;
	bool error(decrypt_prv(pub_a, old_password_a, prv));
	if (!error)
	{
		czr::key_content kc(gen_key_content(prv, new_password_a));
		add_or_update_key(transaction_a, kc);
	}
	return error;
}

bool czr::key_manager::remove(MDB_txn * transaction_a, czr::public_key const & pub_a, std::string const & password_a)
{
	czr::raw_key prv;
	bool error(decrypt_prv(pub_a, password_a, prv));
	if (!error)
	{
		{
			std::lock_guard<std::mutex> lock(unlocked_mutex);
			unlocked.erase(pub_a);
		}
		{
			std::lock_guard<std::mutex> lock(key_contents_mutex);
			key_contents.erase(pub_a);
		}
		key_del(transaction_a, pub_a);
	}

	return error;
}

bool czr::key_manager::import(MDB_txn * transaction_a, std::string const & json_a, key_content & kc_a)
{
	bool error(false);
	czr::key_content kc(error, json_a);
	if (!error)
	{
		add_or_update_key(transaction_a, kc);
		kc_a = kc;
	}

	return error;
}

bool czr::key_manager::decrypt_prv(czr::public_key const & pub_a, std::string const & password_a, czr::raw_key & prv)
{
	bool error(false);
	czr::key_content kc;
	{
		std::lock_guard<std::mutex> lock(key_contents_mutex);
		if (key_contents.count(pub_a))
			kc = key_contents[pub_a];
		else
			error = true;
	}

	if (!error)
		error = decrypt_prv(kc, password_a, prv);

	return error;
}

bool czr::key_manager::decrypt_prv(czr::key_content const & kc_a, std::string const & password_a, czr::raw_key & prv)
{
	bool error(false);

	czr::raw_key derive_pwd;
	kdf.phs(derive_pwd, password_a, kc_a.kdf_salt);

	prv.decrypt(kc_a.ciphertext, derive_pwd, kc_a.iv);

	czr::public_key compare;
	ed25519_publickey(prv.data.bytes.data(), compare.bytes.data());
	if (kc_a.account != compare)
	{
		error = true;
	}

	return error;
}

bool czr::key_manager::is_locked(czr::public_key const & pub_a)
{
	std::lock_guard<std::mutex> lock(unlocked_mutex);
	return unlocked.count(pub_a) > 0;
}

bool czr::key_manager::find_unlocked_prv(czr::public_key const & pub_a, czr::raw_key & prv)
{
	bool exists(true);
	std::lock_guard<std::mutex> lock(unlocked_mutex);
	if (unlocked.count(pub_a))
		prv.data = unlocked[pub_a];
	else
		exists = false;
	return exists;
}

void czr::key_manager::lock(czr::public_key const & pub_a)
{
	std::lock_guard<std::mutex> lock(unlocked_mutex);
	unlocked.erase(pub_a);
}

bool czr::key_manager::unlock(czr::public_key const & pub_a, std::string const & password_a)
{
	czr::raw_key prv;
	bool error(decrypt_prv(pub_a, password_a, prv));
	if (!error)
	{
		std::lock_guard<std::mutex> lock(unlocked_mutex);
		unlocked[pub_a] = prv.data;
	}
	
	return error;
}

void czr::key_manager::write_backup(czr::public_key const & account, std::string const & json)
{
	std::ofstream backup_file;
	std::string file_name((backup_path / (account.to_account() + ".json")).string());
	backup_file.open(file_name);
	if (!backup_file.fail())
	{
		backup_file << json;
	}
}

czr::key_content czr::key_manager::gen_key_content(czr::raw_key const & prv, std::string const & password_a)
{
	czr::uint256_union kdf_salt;
	random_pool.GenerateBlock(kdf_salt.bytes.data(), kdf_salt.bytes.size());

	czr::raw_key derive_pwd;
	kdf.phs(derive_pwd, password_a, kdf_salt);

	czr::uint128_union iv;
	random_pool.GenerateBlock(iv.bytes.data(), iv.bytes.size());

	czr::uint256_union ciphertext;
	ciphertext.encrypt(prv, derive_pwd, iv);

	czr::public_key pub;
	ed25519_publickey(prv.data.bytes.data(), pub.bytes.data());

	czr::key_content kc(pub, kdf_salt, iv, ciphertext);
	return kc;
}

void czr::key_manager::add_or_update_key(MDB_txn * transaction_a, czr::key_content const & kc)
{
	{
		std::lock_guard<std::mutex> lock(key_contents_mutex);
		key_contents[kc.account] = kc;
	}
	key_put(transaction_a, kc.account, kc);
	write_backup(kc.account, kc.to_json());
}

bool czr::key_manager::key_get(MDB_txn * transaction_a, czr::public_key const & pub_a, czr::key_content & content)
{
	czr::mdb_val value;
	auto status(mdb_get(transaction_a, keys, czr::mdb_val(pub_a), value));
	assert(status == 0 || status == MDB_NOTFOUND);
	bool result(false);
	if (status == MDB_NOTFOUND)
	{
		result = true;
	}
	else
	{
		content = czr::key_content(value);
		assert(!result);
	}
	return result;
}

void czr::key_manager::key_put(MDB_txn * transaction_a, czr::public_key const & pub_a, czr::key_content const & content)
{
	auto status(mdb_put(transaction_a, keys, czr::mdb_val(pub_a), content.val(), 0));
	assert(status == 0);
}

void czr::key_manager::key_del(MDB_txn * transaction_a, czr::public_key const & pub_a)
{
	auto status(mdb_del(transaction_a, keys, czr::mdb_val(pub_a), nullptr));
	assert(status == 0 || status == MDB_NOTFOUND);
}

