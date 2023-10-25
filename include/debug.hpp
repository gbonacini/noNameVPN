// -----------------------------------------------------------------
// Copyright (C) 2023  Gabriele Bonacini
// Debugmode - log file handler
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

#include <exception>
#include <cstdio>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

#ifdef MT_DEBUG
    #include <mutex>
#endif 

#include <anyexcept.hpp>

namespace debugmode {

    enum DEBUG_MODE : unsigned long { ERR_DEBUG=0, STD_DEBUG=1, VERBOSE_DEBUG=2 };

    class Debug{
        protected:
            static inline DEBUG_MODE   debug_mode { DEBUG_MODE::STD_DEBUG };

        public:
            explicit          Debug(DEBUG_MODE level = ERR_DEBUG)                             noexcept;
            void              init(const std::string& filepath)                      const    anyexcept;
            static void       setDebugLevel(DEBUG_MODE level = ERR_DEBUG)                     noexcept ;
            static DEBUG_MODE getDebugLevel(void)                                             noexcept ;
            static void       printLog(const std::string& msg, DEBUG_MODE minLevel)           noexcept ;
            static void       printLog(const char* const msg, DEBUG_MODE minLevel)            noexcept ;
            static void       trace(const char* header,
                                    const uint8_t* buff,
                                    const size_t size,
                                    size_t begin,
                                    size_t end)                                               noexcept;
            static void       trace(const std::string& header,
                                   const std::vector<uint8_t>* buff,
                                   size_t begin,
                                   size_t end,
                                   size_t max)                                                noexcept;
            static void       traceStdout(const char* header,
                                    const uint8_t* buff,
                                    const size_t size,
                                    size_t begin,
                                    size_t end)                                               noexcept;
            static void       traceStdout(const std::string& header,
                                   const std::vector<uint8_t>* buff,
                                   size_t begin,
                                   size_t end,
                                   size_t max)                                                noexcept;
    };

    #ifdef MT_DEBUG

    class DebugMt : public Debug{
        private:
            static inline std::mutex   logMtx,
                                       screenMtx;

        public:
            explicit          DebugMt(DEBUG_MODE level = ERR_DEBUG)                           noexcept;

            static void       printLog(const std::string& msg, DEBUG_MODE minLevel)           noexcept ;
            static void       printLog(const char* const msg, DEBUG_MODE minLevel)            noexcept ;
            static void       trace(const char* header,
                                    const uint8_t* buff,
                                    const size_t size,
                                    size_t begin,
                                    size_t end)                                               noexcept;
            static void       trace(const std::string& header,
                                   const std::vector<uint8_t>* buff,
                                   size_t begin,
                                   size_t end,
                                   size_t max)                                                noexcept;
            static void       traceStdout(const char* header,
                                    const uint8_t* buff,
                                    const size_t size,
                                    size_t begin,
                                    size_t end)                                               noexcept;
            static void       traceStdout(const std::string& header,
                                   const std::vector<uint8_t>* buff,
                                   size_t begin,
                                   size_t end,
                                   size_t max)                                                noexcept;
    };
    #endif

    class DebugException final : public std::exception {
        public:
           DebugException(std::string& errString);
           DebugException(std::string&& errString);
           const char* what(void)                                                        const noexcept override;

        private:
           std::string errorMessage;
    };

} // End namespace debugmode
