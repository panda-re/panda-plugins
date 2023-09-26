#ifndef _TUPLE_HASH_H
#define _TUPLE_HASH_H

// Source: http://stackoverflow.com/a/9815205 Credit to Stack Overflow User Kerrek SB 2012

#include <functional>
#include <tuple>
#include <utility>

template <class T> inline void hash_combine(std::size_t& seed, const T& v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

template <class Tuple, std::size_t Index = std::tuple_size<Tuple>::value - 1>
struct tuple_hash_impl {
    static inline void apply(std::size_t& seed, Tuple const& tuple)
    {
        tuple_hash_impl<Tuple, Index - 1>::apply(seed, tuple);
        hash_combine(seed, std::get<Index>(tuple));
    }
};

template <class Tuple> struct tuple_hash_impl<Tuple, 0> {
    static inline void apply(std::size_t& seed, Tuple const& tuple)
    {
        hash_combine(seed, std::get<0>(tuple));
    }
};

namespace std
{
template <typename S, typename T> struct hash<pair<S, T>> {
    inline size_t operator()(const pair<S, T>& v) const
    {
        size_t seed = 0;
        ::hash_combine(seed, v.first);
        ::hash_combine(seed, v.second);
        return seed;
    }
};

template <typename... Args> struct hash<tuple<Args...>> {
    inline size_t operator()(const tuple<Args...>& v) const
    {
        size_t seed = 0;
        tuple_hash_impl<tuple<Args...>>::apply(seed, v);
        return seed;
    }
};
} // namespace std
#endif // _TUPLE_HASH_H
