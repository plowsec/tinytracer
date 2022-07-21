#define _GNU_SOURCE
#include "snapshot.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include <string.h>
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

namespace snapshot {
    

    const std::string SNAPSHOT_BASEPATH = "/home/vlad/dbg/UnicornContext_20220718_144209/";
    const std::string CONFIG = "_index.json";
    
    void load_regs(json json_regs) {

        for (auto& el : json_regs.items()) {
            std::cout << "key: " << el.key() << ", value:" << el.value() << '\n';
        }
    }

    void load_segments(json json_segments) {


        for (auto& el : json_segments) {

            if(!el.at("permissions").at("w")) {
                continue; //only care about writable memory segments
            }

            std::cout << "Name: " << std::hex << el.at("name") << std::endl;
            std::cout << "Start: " << std::hex << el.at("start") << std::endl;
            std::cout << "End: " << std::hex << el.at("end") << std::endl;
            std::cout << "Snapshot path: " << std::hex << el.at("content_file") << std::endl;
        }
        
    }
    
    void load_snapshot() {

        // read a JSON file
        std::ifstream i(SNAPSHOT_BASEPATH + CONFIG);
        json j;
        i >> j;

        auto arch = j.at("arch").at("arch");
        std::cout << "JSON: " << arch << std::endl;
        assert(arch == "x64");

        load_regs(j.at("regs"));
        load_segments(j.at("segments"));
    }



}


int main(void) {

    snapshot::load_snapshot();
    return 0;
}