#pragma once

#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <czr/node/utility.hpp>
#include <unordered_map>

namespace czr
{
void error_response (std::function<void(boost::property_tree::ptree const &)> response_a, std::string const & message_a);
class node;
/** Configuration options for RPC TLS */
class rpc_secure_config
{
public:
	rpc_secure_config ();
	void serialize_json (boost::property_tree::ptree &) const;
	bool deserialize_json (boost::property_tree::ptree const &);

	/** If true, enable TLS */
	bool enable;
	/** If true, log certificate verification details */
	bool verbose_logging;
	/** Must be set if the private key PEM is password protected */
	std::string server_key_passphrase;
	/** Path to certificate- or chain file. Must be PEM formatted. */
	std::string server_cert_path;
	/** Path to private key file. Must be PEM formatted.*/
	std::string server_key_path;
	/** Path to dhparam file */
	std::string server_dh_path;
	/** Optional path to directory containing client certificates */
	std::string client_certs_path;
};
class rpc_config
{
public:
	rpc_config ();
	rpc_config (bool);
	void serialize_json (boost::property_tree::ptree &) const;
	bool deserialize_json (boost::property_tree::ptree const &);
	boost::asio::ip::address address;
	uint16_t port;
	bool enable_control;
	rpc_secure_config secure;
};
enum class payment_status
{
	not_a_status,
	unknown,
	nothing, // Timeout and nothing was received
	//insufficient, // Timeout and not enough was received
	//over, // More than requested received
	//success_fork, // Amount received but it involved a fork
	success // Amount received
};
class wallet;
class rpc
{
public:
	rpc (boost::asio::io_service &, czr::node &, czr::rpc_config const &);
	void start ();
	virtual void accept ();
	void stop ();
	boost::asio::ip::tcp::acceptor acceptor;
	std::mutex mutex;
	czr::rpc_config config;
	czr::node & node;
	bool on;
	static uint16_t const rpc_port = czr::czr_network == czr::czr_networks::czr_live_network ? 7076 : 55000;
};
class rpc_connection : public std::enable_shared_from_this<czr::rpc_connection>
{
public:
	rpc_connection (czr::node &, czr::rpc &);
	virtual void parse_connection ();
	virtual void read ();
	virtual void write_result (std::string body, unsigned version);
	std::shared_ptr<czr::node> node;
	czr::rpc & rpc;
	boost::asio::ip::tcp::socket socket;
	boost::beast::flat_buffer buffer;
	boost::beast::http::request<boost::beast::http::string_body> request;
	boost::beast::http::response<boost::beast::http::string_body> res;
	std::atomic_flag responded;
};
class rpc_handler : public std::enable_shared_from_this<czr::rpc_handler>
{
public:
	rpc_handler (czr::node &, czr::rpc &, std::string const &, std::function<void(boost::property_tree::ptree const &)> const &);
	void process_request ();
	void account_balance ();
	void account_block_count ();
	void account_create ();
	void account_get ();
	void account_key ();
	void account_list ();
	void account_move ();
	void account_remove ();
	void accounts_balances ();
	void accounts_create ();
	void accounts_frontiers ();
	void account_validate();
	void block ();
	void blocks ();
	void block_count ();
	void deterministic_key ();
	void key_create ();
	void password_change ();
	void password_enter ();
	void password_valid (bool wallet_locked);
	void send ();
	void stop ();
	void version ();
	void wallet_add ();
	void wallet_balances ();
	void wallet_change_seed ();
	void wallet_contains ();
	void wallet_create ();
	void wallet_destroy ();
	void wallet_export ();
	void wallet_lock ();	
	void witness_set();
	void witness_list();
	std::string body;
	czr::node & node;
	czr::rpc & rpc;
	boost::property_tree::ptree request;
	std::function<void(boost::property_tree::ptree const &)> response;
};
/** Returns the correct RPC implementation based on TLS configuration */
std::unique_ptr<czr::rpc> get_rpc (boost::asio::io_service & service_a, czr::node & node_a, czr::rpc_config const & config_a);
}
