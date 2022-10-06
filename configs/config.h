#ifndef CONFIG_H
#define CONFIG_H

namespace config
{
    extern uint64_t plain_mod;
    extern uint64_t mod_degree;
    extern int seclevel;
    extern bool use_bsgs;  // used when creating the galois key
}

#endif