#include "block.h"

std::ostream& operator<<(std::ostream& os, const Block& b)
{
    os << "Block("
       << "pc=" << std::hex << b.pc << ", "
       << "rva=" << b.rva << ", "
       << "icount=" << std::dec << b.icount << ", "
       << "size=" << b.size << ", "
       << "hits=" << b.hits << ")";

    if (b.disassembly != "") {
        os << std::endl << b.disassembly;
    }

    return os;
}

bool Block::operator==(const Block& other) const
{
    return (rva == other.rva) && (icount == other.icount) && (size == other.size);
}

void Block::disassemble(CPUState* env)
{
    // get the disassembly of this block and store it in our private variable
    if (has_disassembly) {
        return;
    }

    char instructions[4096];
    panda_virtual_memory_rw(env, this->pc, (uint8_t*)instructions, this->size, false);

    // panda_disas only takes a c stream as input, so we have to make one
    char* assembly = NULL;
    size_t size = 0;
    FILE* a = open_memstream(&assembly, &size);
    panda_disas(a, instructions, this->size);
    fclose(a);

    disassembly = assembly;
    free(assembly);
    has_disassembly = true;
}

void Block::hit() { hits++; }
