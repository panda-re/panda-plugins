#include "vad.h"

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

uint16_t get_page_shift()
{
    // For 4K pages
    return 12;
}

const std::pair<uint64_t, uint64_t> NO_MATCH = {0, 0};

std::pair<uint64_t, uint64_t> find_vad_range(osi::i_t& eprocess, uint64_t addr)
{
    auto page_shift = get_page_shift();
    uint64_t target_vpn = addr >> page_shift;
    auto vad_root = eprocess["VadRoot"];
    auto working = vad_root["BalancedRoot"];

    while (working.get_address() != 0) {
        // Does this node contain target_vpn?
        auto starting_vpn = working["StartingVpn"].getu();
        auto ending_vpn = working["EndingVpn"].getu();
        if ((starting_vpn <= target_vpn) && (target_vpn <= ending_vpn)) {
            return std::pair<uint64_t, uint64_t>(starting_vpn << page_shift,
                                                 ending_vpn << page_shift);
        }
        // Check the left arm
        if (target_vpn < starting_vpn) {
            auto left_child = working("LeftChild");
            if (left_child.get_address() == 0) {
                return NO_MATCH;
            }
            working = left_child;
            continue;
        } else if (ending_vpn < target_vpn) {
            // Check the right arm
            auto right_child = working("RightChild");
            if (right_child.get_address() == 0) {
                return NO_MATCH;
            }
            working = right_child;
            continue;
        } else {
            return NO_MATCH;
        }
    }

    return NO_MATCH;
}
