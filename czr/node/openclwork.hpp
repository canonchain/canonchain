#pragma once

#include <czr/node/xorshift.hpp>

#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>

#include <map>
#include <mutex>
#include <vector>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#include <CL/cl.h>
#endif

namespace czr
{
	class logging;
	class opencl_platform
	{
	public:
		cl_platform_id platform;
		std::vector<cl_device_id> devices;
	};
	class opencl_environment
	{
	public:
		opencl_environment(bool &);
		void dump(std::ostream & stream);
		std::vector<czr::opencl_platform> platforms;
	};
	union uint256_union;
	class work_pool;
	class opencl_config
	{
	public:
		opencl_config();
		opencl_config(unsigned, unsigned, unsigned);
		void serialize_json(boost::property_tree::ptree &) const;
		bool deserialize_json(boost::property_tree::ptree const &);
		unsigned platform;
		unsigned device;
		unsigned threads;
	};
	class opencl_work
	{
	public:
		opencl_work(bool &, czr::opencl_config const &, czr::opencl_environment &, czr::logging &);
		~opencl_work();
		boost::optional<uint64_t> generate_work(czr::uint256_union const &);
		static std::unique_ptr<opencl_work> create(bool, czr::opencl_config const &, czr::logging &);
		czr::opencl_config const & config;
		std::mutex mutex;
		cl_context context;
		cl_mem attempt_buffer;
		cl_mem result_buffer;
		cl_mem item_buffer;
		cl_program program;
		cl_kernel kernel;
		cl_command_queue queue;
		czr::xorshift1024star rand;
		czr::logging & logging;
	};
}
