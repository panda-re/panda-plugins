#ifndef __VAD_H__

#include "common.h"

#include <offset/i_t.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

std::pair<uint64_t, uint64_t> find_vad_range(osi::i_t& eprocess, uint64_t addr);

#define __VAD_H__
#endif
