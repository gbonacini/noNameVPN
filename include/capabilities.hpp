// -----------------------------------------------------------------
// Capabilities - Linux capabilities handler
// Copyright (C) 2017-2023  Gabriele Bonacini
//
// This program is distributed under dual license:
// - Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License
// for non commercial use, the license has the following terms:
// * Attribution — You must give appropriate credit, provide a link to the license,
// and indicate if changes were made. You may do so in any reasonable manner,
// but not in any way that suggests the licensor endorses you or your use.
// * NonCommercial — You must not use the material for commercial purposes.
// A copy of the license it's available to the following address:
// http://creativecommons.org/licenses/by-nc/4.0/
// - For commercial use a specific license is available contacting the author.
// -----------------------------------------------------------------

#pragma once

#include <sys/capability.h>

#include <string>
#include <anyexcept.hpp>
#include <debug.hpp>

namespace capabilities {

    class Capability{
            public:
                             Capability(void)                                 noexcept;
                             ~Capability(void)                                noexcept;
                   void      init(bool noRoot)                                anyexcept;
                   void      printStatus(void)                         const  noexcept;
                   void      getCredential(void)                              anyexcept;
                   void      reducePriv(const std::string& capText)           anyexcept;

            private:
                   uid_t     uid,
                             euid;
                   gid_t     gid,
                             egid;
                   cap_t     cap,
                             newcaps;
    };

    class CapabilityException final{
            public:
               CapabilityException(std::string&  errString);
               CapabilityException(std::string&& errString);
               std::string what(void)                                  const  noexcept;
            private:
               std::string errorMessage;
    };

} // End namespace capabilities
