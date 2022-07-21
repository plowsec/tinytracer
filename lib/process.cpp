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