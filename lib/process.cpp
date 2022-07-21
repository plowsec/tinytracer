#include <iostream>
#include <fstream>
#include <assert.h>

// check if a process is 32-bit or 64-bit
bool is_32_bit(pid_t pid) {

    std::string filename = "/proc/" + std::to_string(pid) + "/exe";
    std::ifstream i(filename);
    i.seekg(4);
    int value = i.get();

    std::cout << "Got value " << std::hex << value << std::endl;
    assert(value == 1 || value == 2);
    return value == 1;
}

long long unsigned get_remote_base_address(pid_t pid) {
    std::string filename = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream i(filename);

    if(!i.is_open()) {
        throw std::runtime_error("Can't open /proc/child_pid/maps");
    }

    std::string line;
    std::getline(i, line);

    auto token = line.substr(0,line.find("-"));
    return std::stoull(token, nullptr, 16);
}

