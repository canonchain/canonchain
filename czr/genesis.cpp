#include <czr/genesis.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

char const * test_genesis_data = R"%%%({
    "from":"czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
    "to":"czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh01",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh02",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh03",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh04",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh05",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh06",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh07",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh08",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh09",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh10", 
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh11",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh12"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

char const * beta_genesis_data = R"%%%({
    "from":"czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
    "to":"czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh01",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh02",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh03",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh04",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh05",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh06",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh07",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh08",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh09",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh10",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh11",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh12"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"exec_timestamp":"1526568538",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

char const * live_genesis_data = R"%%%({
    "from":"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
    "to":"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
        "czr_3s1spjyzcwg7p9nfmm4965xd1hjrgqtoaczeme87ocgoib44q89knik1ee7g",
    	"czr_1r8bg4xbdoh5nnbqmrw78tq7o11nxcn8bwa9auf41ethequ671y6xpxh6fx6",
		"czr_1iputr871epf46jjyngx6iado7s1ifxx6nygbkhjooobh3a3ww851ahp1ea6",
        "czr_1ont3z71drekjypamicsex8x8jtyfd4pa8ej84kmw9yrzabad9dx8484wy9k",
		"czr_3ppbto8ybjoezthtyza1erf8jyikn67obd31pt896uwpc4pwzkwdt4swsy67",
		"czr_3ahughpq1jj5418drr5gukgwxrpzzkwtzcxka898i55uykdnfs6byw97x41n",
		"czr_1g1xj36kskiutcdr8bsdm98o14pfp86pae96nwy45tct1mxsrifzkkktngwf",
    	"czr_35unef35js4xh1ze1rjt68ardh6bgzd7un5h9umfss3qhik644pbsixyuxup",
		"czr_1i6q16o14cq31oppqmtp9q69phap54hiw7z9uq1qdzzeyi1x7nztd4zp8pex",
		"czr_3gj7hxxwrxu7n3jqkba9wpesojsqirg1njus6jq4zazmfawyw77nf4y6kkmb",
		"czr_1d3uq9ajqehy3wxq435m993cm6nutmtf7t7keicdunsr7z1615x9hj9ousgb",
		"czr_1qu31ysq1yyq7ip1fbkua9xh5bd1jgj787xyg54uqptb5oiiyaxysf3fdzce"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"exec_timestamp":"1526568538",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

void czr::genesis::try_initialize(MDB_txn * transaction_a, czr::block_store & store_a)
{
	bool exists(!store_a.genesis_hash_get(transaction_a, block_hash));
	if (exists)
		return;

	auto genesis_data(czr::czr_network == czr::czr_networks::czr_test_network ? test_genesis_data : czr::czr_network == czr::czr_networks::czr_beta_network ? beta_genesis_data: live_genesis_data);
	std::stringstream istream(genesis_data);

	boost::property_tree::ptree tree;
	boost::property_tree::read_json(istream, tree);
	bool error;
	std::unique_ptr<czr::block> block(new czr::block(error, tree));
	if (error)
		throw std::runtime_error("deserialize genesis block error");

	block_hash = block->hash();
	store_a.genesis_hash_put(transaction_a, block_hash);
	store_a.block_put(transaction_a, block_hash, *block);

	//block state
	czr::block_state block_state;
	block_state.is_fork = false;
	block_state.is_invalid = false;
	block_state.is_fail = false;
	block_state.is_free = true;
	block_state.is_on_main_chain = 1;
	block_state.main_chain_index = 0;
	block_state.latest_included_mc_index = boost::none;
	block_state.is_stable = 1;
	block_state.level = 0;
	block_state.witnessed_level = 0;
	block_state.best_parent = 0;
	block_state.timestamp = block->hashables.exec_timestamp;
	block_state.from_state = 0;
	block_state.to_state = 0;
	store_a.block_state_put(transaction_a, block_hash, block_state);

	//mci
	store_a.main_chain_put(transaction_a, *block_state.main_chain_index, block_hash);
	store_a.mci_block_put(transaction_a, czr::mci_block_key(*block_state.main_chain_index, block_hash));

	//free
	store_a.free_put(transaction_a, czr::free_key(block_state.witnessed_level, block_state.level, block_hash));

	//to account state
	czr::account_state to_state(block->hashables.to, block_hash, 0, block->hashables.amount);
	store_a.account_state_put(transaction_a, to_state.hash(), to_state);
	store_a.latest_account_state_put(transaction_a, block->hashables.to, to_state);


	//witness list
	czr::witness_list_info wl_info(block->hashables.witness_list);
	store_a.block_witness_list_put(transaction_a, block_hash, wl_info);
	czr::witness_list_key wl_key(wl_info.hash(), *block_state.main_chain_index);
	store_a.witness_list_hash_block_put(transaction_a, wl_key, block_hash);

	//summary hash
	std::vector<czr::summary_hash> p_summary_hashs; //no parents
	std::set<czr::summary_hash> summary_skiplist; //no skiplist
	czr::summary_hash summary_hash = czr::summary::gen_summary_hash(block_hash, p_summary_hashs, summary_skiplist,
		block_state.is_fork, block_state.is_invalid, block_state.is_fail, block_state.from_state, block_state.to_state);
	store_a.block_summary_put(transaction_a, block_hash, summary_hash);
	store_a.summary_block_put(transaction_a, summary_hash, block_hash);
}

czr::block_hash czr::genesis::block_hash(0);

