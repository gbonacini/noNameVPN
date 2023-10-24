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

#include <capabilities.hpp>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>

#include <cstring>
#include <StringUtils.hpp>

namespace capabilities{

    using std::string,
          std::to_string,
          debugmode::Debug,
          debugmode::DEBUG_MODE,
          stringutils::mergeStrings;

    Capability::Capability(void)  noexcept
        : uid{getuid()},       euid{geteuid()},
          gid{getgid()},       egid{getegid()},
          cap{cap_get_proc()}, newcaps{cap}
    {}

    void  Capability::init(bool noRoot)  anyexcept{
        if(noRoot){
             if(uid == 0 || gid == 0 ){
                string errmsg { "Root user or group are not permitted: use a standard user instead." };
                Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
                throw CapabilityException(errmsg);
             }
        }
    }

    Capability::~Capability(void) noexcept{
          cap_free(cap);
          cap_free(nullptr);
    }

    void Capability::printStatus(void) const noexcept{
           Debug::printLog(mergeStrings({ "UID: ", to_string(uid).c_str(), " EUID: ", to_string(euid).c_str(),
                                          "\nGID: ", to_string(gid).c_str(), " GID:  ", to_string(egid).c_str(),
                                          "\nRunning with capabilities: ",  cap_to_text(cap, nullptr), "\n"
                                       }),
                           DEBUG_MODE::VERBOSE_DEBUG);
    }

    void Capability::getCredential(void) anyexcept{
           uid  = getuid();
           euid = geteuid();
           gid  = getgid();
           egid = getegid();
           cap  = cap_get_proc();
           if(cap == nullptr){
               string errmsg { mergeStrings({ "Capability error reading credential: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw CapabilityException(errmsg);
           }
    }

    void Capability::reducePriv(const string& capText) noexcept(false){
           if(prctl(PR_SET_KEEPCAPS, 1) ==  -1){
               string errmsg { mergeStrings({ "Capability setting : prctl error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw CapabilityException(errmsg);
           }

           newcaps  = cap_from_text(capText.c_str());

           if(setresgid(gid, gid, gid)  ==  -1){
               string errmsg { mergeStrings({ "Capability setting : setresgid error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw CapabilityException(errmsg);
           }
           if(setresuid(uid, uid, uid)  ==  -1){
               string errmsg { mergeStrings({ "Capability setting : setresuid error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw CapabilityException(errmsg);
           }
           if(cap_set_proc(newcaps)     ==  -1){
               string errmsg { mergeStrings({ "Capability setting : cap_set_proc error: ", strerror(errno)}) };
               Debug::printLog(errmsg, DEBUG_MODE::ERR_DEBUG);
               throw CapabilityException(errmsg);
           }
    }

    CapabilityException::CapabilityException(string& errString)
        :  errorMessage{errString}
    {}

    CapabilityException::CapabilityException(string&& errString)
        :  errorMessage{errString}
    {}

    string CapabilityException::what() const noexcept{
           return errorMessage;
    }

} // End namespace capabilities
