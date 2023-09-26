#ifndef _BASE_64_H
#define _BASE_64_H

// TODO This is from freely licensed code on the internet. Might want to
// find a better implementation, or at least check this one for accuracy

#include <cstdio>
#include <memory>
#include <vector>

const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::unique_ptr<std::vector<char>> base64_encode(const std::vector<uint8_t>& input)
{
    auto retvec = std::unique_ptr<std::vector<char>>(new std::vector<char>());

    uint8_t c0, c1, c2, c3;
    uint32_t sum = 0;

    auto data = input.data();
    for (unsigned ix = 0; ix < input.size(); ix += 3) {
        sum = ((uint32_t)data[ix]) << 16;

        if ((ix + 1) < input.size()) {
            sum += ((uint32_t)data[ix + 1]) << 8;
        }
        if ((ix + 2) < input.size()) {
            sum += ((uint32_t)data[ix + 2]);
        }

        c0 = (uint8_t)(sum >> 18) & 0x3f;
        c1 = (uint8_t)(sum >> 12) & 0x3f;
        c2 = (uint8_t)(sum >> 6) & 0x3f;
        c3 = (uint8_t)(sum)&0x3f;

        retvec->push_back(alphabet[c0]);
        retvec->push_back(alphabet[c1]);

        if ((ix + 1) < input.size()) {
            retvec->push_back(alphabet[c2]);
        }
        if ((ix + 2) < input.size()) {
            retvec->push_back(alphabet[c3]);
        }
    }

    int padcount = input.size() % 3;
    if (padcount > 0) {
        for (; padcount < 3; padcount++) {
            retvec->push_back('=');
        }
    }
    retvec->push_back(0);
    return retvec;
}

#endif
