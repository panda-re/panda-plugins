#ifndef OSCALL_ARGUMENT_H
#define OSCALL_ARGUMENT_H

#include "exec/cpu-defs.h"
#include <memory>
#include <vector>

enum ArgIoType { IN = 1, IN_OPT, INOUT, INOUT_OPT, OUT, OUT_OPT, UNKNOWN };

typedef enum { TYPE_ARG, INPUT_LENGTH_ARG, OUTPUT_LENGTH_ARG } ArgLookupType;

typedef const char* ArgType;

class ArgSpec
{
private:
    uint8_t m_position;
    std::string m_name;
    ArgType m_arg_type;
    ArgIoType m_io_type;
    int8_t m_type_arg_pos;
    int8_t m_length_in_arg_pos;
    int8_t m_length_out_arg_pos;

public:
    ArgSpec(uint8_t pos, ArgIoType atype_io, ArgType atype, int8_t type_arg_pos,
            int8_t length_in_arg_pos, int8_t length_out_arg_pos, const std::string& name)
        : m_position(pos), m_name(name), m_arg_type(atype), m_io_type(atype_io),
          m_type_arg_pos(type_arg_pos), m_length_in_arg_pos(length_in_arg_pos),
          m_length_out_arg_pos(length_out_arg_pos)
    {
    }

    uint8_t position() const { return m_position; }
    const char* name() const { return m_name.c_str(); }
    ArgType type() const { return m_arg_type; }
    ArgIoType io_type() const { return m_io_type; }

    // These returns the argument number that can be used to determine
    // additional information on this argument, or -1 if UNKNOWN/DNE
    int8_t type_arg_pos() const { return m_type_arg_pos; }
    int8_t input_length_arg_pos() const { return m_length_in_arg_pos; }
    int8_t output_length_arg_pos() const { return m_length_out_arg_pos; }
};

class Argument
{ // inherited from in trace_engine currently
public:
    virtual target_ulong value() const = 0;
    virtual const ArgSpec* specification() const = 0;
};

typedef std::shared_ptr<std::vector<std::unique_ptr<Argument>>> ArgumentVector;

class CallContext
{
public:
    virtual target_ulong call_id() = 0;
    virtual const char* call_name() = 0;
    virtual ArgumentVector args() = 0;
    virtual void set_guid(int64_t new_guid) = 0;
    virtual int64_t get_guid() = 0;
    virtual bool set_tid(uint64_t) = 0;
    virtual uint64_t get_tid() = 0;
    const char* get_call_module() { return nullptr; };
};

const char* arg_io_type_name(ArgIoType iotype);

#endif
