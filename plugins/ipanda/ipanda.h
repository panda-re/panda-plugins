#pragma once

#include "manager.h"
#include <ipanda/panda_x86.h>
/**
 * \brief Bootstrap a plugin to the correct Operating System Introspection object.
 *
 * Note that Introspection will be available ON OR AFTER the first instruction
 * of the replay. Bootstrapping done right before the first instruction, and
 * we cannot guarentee callback ordering.
 *
 * \param target the plugins's "self" pointer
 * \return if the bootstrapping was successful
 */
bool init_ipanda(void* target, std::shared_ptr<IntroPANDAManager>& manager);
