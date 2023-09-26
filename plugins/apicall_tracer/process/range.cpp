#include <memory>
#include <set>

#include "range.h"

void AddressRangeList::add(uint64_t base, uint64_t length)
{
    auto ar = AddressRange(base, length);
    m_ranges->insert(ar);
}

bool AddressRangeList::contains(uint64_t address)
{
    auto target = AddressRange(address, 0);

    if (m_ranges->empty()) {
        return false;
    }

    // Get the first AddressRange with a base address greater than address,
    // then look at the AddressRange before it. Since std::set is ordered, and
    // we are assuming AddressRanges don't overlap, it would be the only AddressRange
    // that can contain address
    std::set<AddressRange>::iterator itr = m_ranges->upper_bound(target);
    if (itr == m_ranges->begin()) {
        if ((*itr).base != target.base) {
            return false;
        }
    } else {
        itr = --itr;
    }

    auto& range = *itr;
    return (range.base <= address) && (address <= range.upper_bound());
}
