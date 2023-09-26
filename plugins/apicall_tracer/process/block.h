#ifndef __BLOCK__

#include "panda/plugin.h"
#include "panda/common.h"
#include <iostream>
#include <sstream>

inline uint64_t block_key(uint64_t pc, uint64_t size) { return pc + size; }

class Block
{
private:
    uint64_t pc;
    uint64_t rva;
    uint32_t icount;
    uint32_t size;
    uint64_t hits;
    std::string disassembly;
    bool has_disassembly;

public:
    Block()
        : pc(0), rva(0), icount(0), size(0), hits(0), disassembly(""),
          has_disassembly(false){};
    Block(uint64_t pc, uint64_t rva, uint64_t icount, uint64_t size)
        : pc(pc), rva(rva), icount(icount), size(size), hits(0), disassembly(""),
          has_disassembly(false){};
    Block(uint64_t pc, uint64_t rva, uint64_t icount, uint64_t size, CPUState* env)
        : pc(pc), rva(rva), icount(icount), size(size), hits(0), disassembly(""),
          has_disassembly(false)
    {
        disassemble(env);
    };

    bool operator==(const Block& other) const;
    bool operator!=(const Block& other) const { return !(*this == other); };
    friend std::ostream& operator<<(std::ostream& os, const Block& b);

    inline uint64_t key() const { return block_key(pc, size); }

    uint64_t get_pc() { return pc; }

    uint64_t get_rva() { return rva; }

    uint32_t get_icount() { return icount; }

    uint32_t get_size() { return size; }

    uint64_t get_hits() { return hits; }

    const std::string& get_disassembly() { return disassembly; }

    void disassemble(CPUState* env);
    void hit();
};

#define __BLOCK__
#endif
