// -----------------------------------------------------------------
// ConfigFile - configuration file handler
// Copyright (C) 2018-2023  Gabriele Bonacini
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

extern "C" {
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
}

#include <string>
#include <array>
#include <map>
#include <anyexcept.hpp>

namespace configFile {

    union ConfigData{
        std::string text;
        long        integer;
        double      floatingPoint;
        bool        boolean;

        explicit ConfigData(std::string&  txt)   noexcept;
        explicit ConfigData(std::string&&  txt)  noexcept;
        explicit ConfigData(const char* txt)     noexcept;
        explicit ConfigData(long num)            noexcept;
        explicit ConfigData(double fl)           noexcept;
        explicit ConfigData(bool bol)            noexcept;
        ~ConfigData(void);
    };

    enum DATA_TYPE : char { BOOLEAN='B', INTEGER='I', FLOATING_POINT='F', TEXT='T'};

    constexpr size_t  MAC_ARRAY_LEN {6 };
    constexpr size_t  IP_ARRAY_LEN  {4 };
    using MacAddr=std::array<uint8_t, MAC_ARRAY_LEN>; 
    using IpAddr=std::array<uint8_t, IP_ARRAY_LEN>;

    class ConfigVar {
        private:
            DATA_TYPE  type;
            ConfigData data;
            bool       empty    {true};
            bool       optional {false};

        public:
            explicit              ConfigVar(std::string&& txt)             noexcept;
            explicit              ConfigVar(std::string& txt)              noexcept;
            explicit              ConfigVar(const char* txt)                noexcept;
            explicit              ConfigVar(long num)                       noexcept;
            explicit              ConfigVar(double fl)                      noexcept;
            explicit              ConfigVar(bool   bl)                      noexcept;

            DATA_TYPE             getDataType(void)                   const noexcept;

            const std::string&    getText(void)                       const anyexcept;  
            void                  getMAC(MacAddr& dst)                const anyexcept;  
            void                  getIp(IpAddr& dst)                  const anyexcept;  
            void                  getIp(std::string& dst)             const anyexcept;  
            uint16_t              getPort(void)                       const anyexcept;
            double                getFloat(void)                      const anyexcept;
            long                  getInteger(void)                    const anyexcept;
            bool                  getBool(void)                       const anyexcept;

            void                  setText(const std::string& val)           anyexcept;  
            void                  setFloat(double val)                      anyexcept;
            void                  setInteger(long val)                      anyexcept;
            void                  setBool(bool val)                         anyexcept;

            void                  setEmpty(bool val)                        noexcept;
            void                  setOptional(bool val)                     noexcept;

            bool                  isNum(void)                         const noexcept;
            bool                  isFloat(void)                       const noexcept;
            bool                  isText(void)                        const noexcept;
            bool                  isBool(void)                        const noexcept;

            bool                  isEmpty(void)                       const noexcept;
            bool                  isOptional(void)                    const noexcept;
    };

    using ConfigEnv=std::map<std::string, ConfigVar>;

    class ConfigFile{
           private:
               std::string configurationFile {""};
               lua_State   *luaState         {nullptr};
               ConfigEnv   configEnv;

               void           cleanConfig(void)                          noexcept;
               std::string    loadString(const std::string& key)         anyexcept;
               long           loadInteger(const std::string& key)        anyexcept;
               double         loadFloat(const std::string& key)          anyexcept;
               bool           loadBool(const std::string& key)           anyexcept;

           public:
               explicit ConfigFile(std::string configfile)               noexcept;
               ~ConfigFile(void)                                         noexcept;
               void     init(void)                                       anyexcept;
               
               void     addLoadableVariable(std::string&& name,
                                            std::string dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            const char* dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            long dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            double dt,
                                            bool optional=false)         anyexcept;
               void     addLoadableVariable(std::string&& name,
                                            bool dt,
                                            bool optional=false)         anyexcept;
               
               void     loadConfig(void)                                 anyexcept;

               const ConfigVar& 
                        getConf(std::string key)                         anyexcept;

    };

     class ConfigFileException final : public std::exception {
        public:
           ConfigFileException(std::string& errString);
           ConfigFileException(std::string&& errString);
           const char* what(void)                             const     noexcept  override;
        private:
           std::string errorMessage;
    };


} // End namespace configFile