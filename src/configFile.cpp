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

#include <configFile.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

#include <stdexcept>

namespace configFile{

    using std::string,
          std::to_string,
          std::stoul,
          std::array,
          std::out_of_range,
          typeutils::safeSizeRange,
          stringutils::mergeStrings;

    ConfigData::ConfigData(string&& txt)  noexcept
         : text{txt}  
    {}

    ConfigData::ConfigData(string& txt)  noexcept
         : text{move(txt)}  
    {}

    ConfigData::ConfigData(const char* txt)   noexcept
         : text{txt}  
    {}

    ConfigData::ConfigData(long num)         noexcept
          : integer{num}
    {}

    ConfigData::ConfigData(double fl)        noexcept
          : floatingPoint{fl}
    {}

    ConfigData::ConfigData(bool bol)         noexcept
          : boolean{bol}
    {}

    ConfigData::~ConfigData(void){
    }

    ConfigVar::ConfigVar(string& txt) noexcept 
          : type { DATA_TYPE::TEXT},
            data {move(txt)}
    {}

    ConfigVar::ConfigVar(string&& txt) noexcept 
          : type { DATA_TYPE::TEXT},
            data {txt}
    {}

    ConfigVar::ConfigVar(const char* txt)  noexcept 
          : type { DATA_TYPE::TEXT},
            data { txt }
    {}

    ConfigVar::ConfigVar(long num)  noexcept 
          : type { DATA_TYPE::INTEGER},
            data { num }
    {}

    ConfigVar::ConfigVar(double fl) noexcept 
          : type { DATA_TYPE::FLOATING_POINT},
            data { fl }
    {}

    ConfigVar::ConfigVar(bool   bl)  noexcept
          : type { DATA_TYPE::BOOLEAN},
            data { bl }
    {}

    DATA_TYPE  ConfigVar::getDataType(void) const noexcept{
          return type;
    }

    const string& ConfigVar::getText(void) const anyexcept{
        if(type == DATA_TYPE::TEXT)
            return data.text;

        throw ConfigFileException("ConfigVar::getText()- wrong type");
    }  

     void ConfigVar::getIp(IpAddr& dst) const anyexcept{
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       {""};

        if(type == DATA_TYPE::TEXT){
            for(auto chr : data.text){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                                countDigits++;
                                if(countDigits > 3)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case '.':
                                countDigits = 0;
                                if(countBlocks + 1 > 3)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 10);
                                if(digit > 255)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - value");
                                dst.at(countBlocks) = digit;
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw ConfigFileException("ConfigVar::getIp()- invalid data");
                }
            }
            if(digitBuff.empty())
                  throw ConfigFileException("ConfigVar::getIp()- invalid data");
            digit = stoul(digitBuff.c_str(), &pos, 10);
            if(digit > 255)
                  throw ConfigFileException("ConfigVar::getIp()- invalid data - value");
            dst.at(countBlocks) = digit;
            
        } else {
            throw ConfigFileException("ConfigVar::getIp()- wrong type");
        }
     }

     void ConfigVar::getIp(string& dst) const anyexcept{
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       {""};

        if(type == DATA_TYPE::TEXT){
            for(auto chr : data.text){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                                countDigits++;
                                if(countDigits > 3)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case '.':
                                countDigits = 0;
                                if(countBlocks + 1 > 3)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 10);
                                if(digit > 255)
                                    throw ConfigFileException("ConfigVar::getIp()- invalid data - value");
                                dst.append(digitBuff).push_back('.');
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw ConfigFileException("ConfigVar::getIp()- invalid data");
                }
            }
            if(digitBuff.empty())
                  throw ConfigFileException("ConfigVar::getIp()- invalid data");
            digit = stoul(digitBuff.c_str(), &pos, 10);
            if(digit > 255)
                  throw ConfigFileException("ConfigVar::getIp()- invalid data - value");
            dst.append(digitBuff);
            
        } else {
            throw ConfigFileException("ConfigVar::getIp()- wrong type");
        }
     }

     void ConfigVar::getMAC(MacAddr& dst) const anyexcept{
        size_t        countDigits     { 0 },
                      countBlocks     { 0 },
                      pos             { 0 };
        unsigned long digit           { 0 };
        string        digitBuff       {""};

        if(type == DATA_TYPE::TEXT){
            for(auto chr : data.text){
                switch(chr){
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                    case 'a':
                    case 'b':
                    case 'c':
                    case 'd':
                    case 'e':
                    case 'f':
                    case 'A':
                    case 'B':
                    case 'C':
                    case 'D':
                    case 'E':
                    case 'F':
                    case 'x':
                    case 'X':
                                countDigits++;
                                if(countDigits > 4)
                                    throw ConfigFileException("ConfigVar::getMAC()- invalid data - digits");
                                digitBuff.push_back(chr);
                        break;
                    case ':':
                                countDigits = 0;
                                if(countBlocks + 1 > 5)
                                    throw ConfigFileException("ConfigVar::getMAC()- invalid data - separators");
                                digit = stoul(digitBuff.c_str(), &pos, 16);
                                if(digit > 255)
                                    throw ConfigFileException("ConfigVar::getMAC()- invalid data - value");
                                dst.at(countBlocks) = digit;
                                digitBuff.clear();
                                countBlocks++;
                        break;

                    default:
                          throw ConfigFileException("ConfigVar::getMAC()- invalid data");
                }
            }
            if(digitBuff.empty())
                  throw ConfigFileException("ConfigVar::getMAC()- invalid data");
            digit = stoul(digitBuff.c_str(), &pos, 16);
            if(digit > 255)
                  throw ConfigFileException("ConfigVar::getMAC()- invalid data - value");
            dst.at(countBlocks) = digit;
            
        } else {
            throw ConfigFileException("ConfigVar::getMAC()- wrong type");
        }
    }  

    double ConfigVar::getFloat(void)  const anyexcept{
        if(type == DATA_TYPE::FLOATING_POINT)
            return data.floatingPoint;

        throw ConfigFileException("ConfigVar::getFloat()- wrong type");
    }

    long  ConfigVar::getInteger(void) const anyexcept{
        if(type == DATA_TYPE::INTEGER)
            return data.integer;

        throw ConfigFileException("ConfigVar::getInteger()- wrong type");
    }

    uint16_t  ConfigVar::getPort(void) const anyexcept{
        if(type == DATA_TYPE::INTEGER)
            return safeSizeRange<uint16_t>(data.integer);

        throw ConfigFileException("ConfigVar::getInteger()- wrong type");
    }

    bool  ConfigVar::getBool(void) const anyexcept{
        if(type == DATA_TYPE::BOOLEAN)
            return data.boolean;

        throw ConfigFileException("ConfigVar::getBool()- wrong type");
    }

    void   ConfigVar::setText(const std::string& val) anyexcept{
        if(type == DATA_TYPE::TEXT)
               data.text = val;
        else
		       throw ConfigFileException(mergeStrings({"ConfigVar::setText()- wrong type", val.c_str()}));  
    }

    void   ConfigVar::setFloat(double val) anyexcept{
        if(type == DATA_TYPE::FLOATING_POINT)
               data.floatingPoint = val;
        else
		       throw ConfigFileException(mergeStrings({"ConfigVar::setFloat()- wrong type", to_string(val).c_str()}));  
    }

    void   ConfigVar::setInteger(long val) anyexcept{
        if(type == DATA_TYPE::INTEGER)
               data.integer = val;
        else
		       throw ConfigFileException(mergeStrings({"ConfigVar::setInteger()- wrong type", to_string(val).c_str()}));  
    }

    void   ConfigVar::setBool(bool val) anyexcept{
        if(type == DATA_TYPE::BOOLEAN)
               data.boolean = val;
        else
		       throw ConfigFileException(mergeStrings({"ConfigVar::setBool()- wrong type", to_string(val).c_str()}));  
    }

     void  ConfigVar::setEmpty(bool val) noexcept{
         empty = val;
     }

     void  ConfigVar::setOptional(bool val) noexcept{
         optional = val;
     }

    bool ConfigVar::isNum(void) const noexcept{
        return type == DATA_TYPE::INTEGER ? true :false;
    }

    bool ConfigVar::isFloat(void) const noexcept{
        return type == DATA_TYPE::FLOATING_POINT ? true :false;
    }

    bool ConfigVar::isText(void) const noexcept{
        return type == DATA_TYPE::TEXT ? true :false;
    }

    bool ConfigVar::isBool(void) const noexcept{
        return type == DATA_TYPE::BOOLEAN ? true :false;
    }

    bool ConfigVar::isEmpty(void) const noexcept{
        return empty;
    }

    bool ConfigVar::isOptional(void) const noexcept{
        return optional;
    }

    ConfigFile::ConfigFile(string configFile)  noexcept 
        : configurationFile { configFile} 
    {}

    void ConfigFile::init(void)  anyexcept{
        luaState = luaL_newstate();
        if(luaState == nullptr)
            throw ConfigFileException("MacNotifyConfig::MacNotifyConfig - lua parser");

        luaL_openlibs(luaState);
    }

    ConfigFile::~ConfigFile(void)  noexcept{
         if(luaState != nullptr) cleanConfig();
    }

    void  ConfigFile::cleanConfig(void) noexcept{
         lua_close(luaState);
         luaState  =  nullptr;
    }

    void  ConfigFile::addLoadableVariable(string&& name, const char* dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, string dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, long dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, double dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }

    void  ConfigFile::addLoadableVariable(string&& name, bool dt, bool optional) anyexcept{
        if(name.empty()) throw ConfigFileException("Error: addOptionalLoadableVariable(): empty name.");

        auto [iterator, result] { configEnv.emplace(name, dt) };
        auto& configValue { iterator->second };
        configValue.setOptional(optional);
    }


    string  ConfigFile::loadString(const string& key) anyexcept{
        string ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 1 ){
		    throw ConfigFileException(mergeStrings({"Error: loadString() - invalid variable : ", key.c_str()}));  
        }else{
            if(lua_isstring(luaState, -1) == 0)
		        throw ConfigFileException(mergeStrings({"Error: loadString(): invalid type : ", key.c_str()}));  
            ret  =   lua_tostring(luaState, -1);
        }
        lua_pop(luaState, 1);

        return ret;
    }

    long  ConfigFile::loadInteger(const string& key) anyexcept{
        long int ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 ){
            int      indicator;

            ret  =  lua_tointegerx(luaState, -1, &indicator);
            if(indicator == 0)
		        throw ConfigFileException(mergeStrings({"Error: loadInteger(): invalid value : ", key.c_str()}));  
        } else {
		    throw ConfigFileException(mergeStrings({"Error: loadInteger() - invalid variable : ", key.c_str()}));  
        }

        lua_pop(luaState, 1);

        return ret;
    }

    double  ConfigFile::loadFloat(const string& key) anyexcept{
        double ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 ){
            int      indicator;

            ret  =  lua_tonumberx(luaState, -1, &indicator);
            if(indicator == 0)
		        throw ConfigFileException(mergeStrings({"Error: loadFloat(): invalid value : ", key.c_str()}));  
        } else {
		    throw ConfigFileException(mergeStrings({"Error: loadFloat() - invalid variable : ", key.c_str()}));  
        }

        lua_pop(luaState, 1);

        return ret;
    }

    bool ConfigFile::loadBool(const string& key)  anyexcept{
        bool ret;
        lua_getglobal(luaState, key.c_str());
        if(lua_isnil(luaState, -1) == 0 )
            ret  =  lua_toboolean(luaState, -1);
        else 
		    throw ConfigFileException(mergeStrings({"Error: loadBool() - invalid variable : ", key.c_str()}));  

        lua_pop(luaState, 1);

        return ret;
    }

    void  ConfigFile::loadConfig(void)  anyexcept{
        if(luaL_loadfile(luaState, configurationFile.c_str()) != 0)
            throw ConfigFileException("Error: Invalid config file name.");

        if(lua_pcall(luaState, 0, 0, 0) != 0)
            throw ConfigFileException("Error: syntax error in config file.");

        bool optionalConf;
        try{
            for (auto &[key, value] : configEnv){
                try{
                    optionalConf = value.isOptional();
                    switch(value.getDataType()){
                        case DATA_TYPE::BOOLEAN :
                              configEnv.at(key).setBool(loadBool(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        case DATA_TYPE::FLOATING_POINT :
                              configEnv.at(key).setFloat(loadFloat(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        case DATA_TYPE::INTEGER :
                              configEnv.at(key).setInteger(loadInteger(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                            case DATA_TYPE::TEXT :
                              configEnv.at(key).setText(loadString(key));
                              configEnv.at(key).setEmpty(false);
                           break;
                        default:
                           throw ConfigFileException("Error: loadConfig() - invalid data type.");
                    }
                }catch(ConfigFileException& ex){
                    if(!optionalConf) throw ex;
                }
            }
        }catch(out_of_range& ex){
            throw ConfigFileException(mergeStrings({"Error: loadconfig: ", ex.what()})); 
        }
    }

    const ConfigVar& ConfigFile::getConf(string key) anyexcept{
        try{ 
            return configEnv.at(key); 
        }catch(...){ 
		    throw ConfigFileException(mergeStrings({"Error: getConf() - invalid key: ", key.c_str()}));  
	    }
    }

    ConfigFileException::ConfigFileException(string& errString)
      :   errorMessage{errString}
    {}

    ConfigFileException::ConfigFileException(string&& errString)
      :   errorMessage{errString}
    {}
 
    const char* ConfigFileException::what() const noexcept{
       return errorMessage.c_str();
    }

} // End namespace configFile
