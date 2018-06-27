#pragma once

#include <functional>
#include <mutex>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

#define STR(s) STR_TEMP(s)
#define STR_TEMP(s) #s

namespace czr
{
// Lower priority of calling work generating thread
void work_thread_reprioritize ();

class error_message
{
public:
	bool error;
	std::string message;
};

}
