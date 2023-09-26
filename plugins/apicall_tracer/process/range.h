#ifndef __BBSTATS_RANGE_H
#define __BBSTATS_RANGE_H

#include <memory>
#include <set>

class AddressRange
{
public:
    uint64_t base;
    uint64_t length;

    AddressRange(uint64_t base, uint64_t length) : base(base), length(length) {}

    uint64_t upper_bound() const { return base + length; }

    bool operator<(const AddressRange& other) const { return this->base < other.base; }
};

class AddressRangeList
{
private:
    std::unique_ptr<std::set<AddressRange>> m_ranges;

public:
    AddressRangeList()
    {
        m_ranges = std::unique_ptr<std::set<AddressRange>>(new std::set<AddressRange>());
    }
    void add(uint64_t base, uint64_t length);
    bool contains(uint64_t address);
};

#endif
