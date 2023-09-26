#include "block.h"
#include "osi/windows/wintrospection.h"
#include <distorm.h>
#include <memory>
#include <string.h>

#define MAX_ASSEMBLY_SIZE 10000
#define MAX_INSTRUCTIONS 1000

bool Block::operator==(const Block& other) const
{
    return (rva == other.rva) && (icount == other.icount) && (size == other.size);
}

void Block::disassemble(struct WindowsProcessOSI* posi)
{
    if (disassembled) {
        return;
    }

    // read memory
    std::unique_ptr<char[]> inst_memory(new char[this->size + 1]);
    posi->vmem->read(this->pc, (uint8_t*)inst_memory.get(), this->size);

    // use distorm to decode memory
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    unsigned int decodedInstructionsCount = 0;

    distorm_decode(0, (const unsigned char*)inst_memory.get(), this->size,
                   ((posi->vmem->get_pointer_width() == 8) ? Decode64Bits : Decode32Bits),
                   decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    for (unsigned int i = 0; i < decodedInstructionsCount; i++) {
        instructions.push_back(
            std::make_tuple(decodedInstructions[i].offset,
                            std::string((char*)decodedInstructions[i].instructionHex.p),
                            std::string((char*)decodedInstructions[i].mnemonic.p),
                            std::string((char*)decodedInstructions[i].operands.p)));
    }

    disassembled = true;
}
