#ifndef __BLOCK__

#include "osi/windows/wintrospection.h"

#include <set>
#include <string>
#include <tuple>
#include <vector>

typedef std::vector<std::tuple<unsigned int, std::string, std::string, std::string>>
    instruction_t;

class Block
{
private:
    uint64_t pc;
    uint64_t rva;
    uint32_t icount;
    uint32_t size;
    uint64_t hits;

    bool disassembled;
    void disassemble(struct WindowsProcessOSI* posi);

    instruction_t instructions;
    std::set<uint64_t> threads;

public:
    Block(uint64_t pc, uint64_t rva, uint64_t icount, uint64_t size,
          struct WindowsProcessOSI* posi)
        : pc(pc), rva(rva), icount(icount), size(size), hits(0), disassembled(false)
    {
        disassemble(posi);
    };

    bool operator==(const Block& other) const;
    bool operator!=(const Block& other) const { return !(*this == other); };

    uint64_t get_pc() { return pc; };

    uint64_t get_rva() { return rva; };

    uint32_t get_icount() { return icount; };

    uint32_t get_size() { return size; };

    uint64_t get_hits() { return hits; };

    const instruction_t& get_instructions() { return instructions; };

    const std::set<uint64_t> get_threads() { return threads; };

    void hit() { ++hits; };

    void executed(uint64_t tid) { threads.insert(tid); };
};

#define __BLOCK__
#endif
