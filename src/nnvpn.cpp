// -----------------------------------------------------------------
// nnvpn - a trivial VPN using OpenSSL
// Copyright (C) 2023  Gabriele Bonacini
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

#include <unistd.h>
#include <stdlib.h>

#include <string>
#include <iostream>

#include <parseCmdLine.hpp>
#include <debug.hpp>
#include <configFile.hpp>
#include <capabilities.hpp>
#include <inetgeneral.hpp>

using namespace std;
using namespace debugmode;
using namespace capabilities;
using namespace inetlib;

using parcmdline::ParseCmdLine;
using configFile::ConfigFileException;
using configFile::ConfigFile;
using configFile::IpAddr;

#ifdef __clang__
  void printInfo(char* cmd) __attribute__((noreturn));
#else
  [[ noreturn ]]
  void printInfo(char* cmd);
#endif

int main(int argc, char** argv){
    const long       MAX_PAYLOAD  { 1500 };
    const char       flags[]      { "hd:f:s"};
    DEBUG_MODE       debugMode    { DEBUG_MODE::ERR_DEBUG };
    string           configFile   { "./nnvpn.lua"};
    int              ret          { 0 };
    ParseCmdLine     pcl          {argc, argv, flags};
    bool             isServer     { false };

    if(pcl.getErrorState()){
        string exitMsg{string("Invalid  parameter or value").append(pcl.getErrorMsg())};
        cerr << exitMsg << "\n";
        printInfo(argv[0]);
    }

    if(pcl.isSet('h')) printInfo(argv[0]);
    if(pcl.isSet('s')) isServer = true;
    if(pcl.isSet('f')) configFile = pcl.getValue('f');

    if(pcl.isSet('d')){
            unsigned long debug{ stoul(pcl.getValue('d')) };
            switch(debug){
                case 0:
                    debugMode = DEBUG_MODE::ERR_DEBUG;
                   break;
                case 1: 
                    debugMode = DEBUG_MODE::STD_DEBUG;
                   break;
                case 2: 
                    debugMode = DEBUG_MODE::VERBOSE_DEBUG;
                   break;
                default:
                    debugMode = DEBUG_MODE::STD_DEBUG;
            }
    }

    uint16_t         port         { 0 };
    long             psize        { MAX_PAYLOAD };
    string           address      { "" },
                     cert         { "" },
                     key          { "" },
                     device       { "" },
                     logFile      { "" };
    try{
         ConfigFile cfg(configFile);
         try{
             cfg.init();
             cfg.addLoadableVariable("address", ""); 
             cfg.addLoadableVariable("port", 8081L, true);
             cfg.addLoadableVariable("psize", MAX_PAYLOAD, true);
             cfg.addLoadableVariable("cert", "");
             cfg.addLoadableVariable("key", "");
             cfg.addLoadableVariable("device", "");
             cfg.addLoadableVariable("log", "");
    
             cfg.loadConfig();
    
             cfg.getConf("address").getIp(address);
             port     = cfg.getConf("port").getPort(); 
             psize    = cfg.getConf("psize").getInteger(); 
             if(psize < 0 || ( psize % MAX_PAYLOAD ) != 0 ) throw ConfigFileException("Invalid payload size");
             cert     = cfg.getConf("cert").getText();
             device   = cfg.getConf("device").getText();
             key      = cfg.getConf("key").getText();
             logFile  = cfg.getConf("log").getText();
         } catch(ConfigFileException& ex){
             ret = 1;
             string msg {"Error loading configuration file: "};
             msg.append(ex.what());
             cerr << msg << "\n";
             printInfo(argv[0]);
             throw string{"Abort."};
         }
  
         Debug debug{debugMode};
         try{
             debug.init(logFile);

         }catch(DebugException& ex){
             ret = 1;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }
 
         Capability cpb;
         try{
             cpb.init(true); 
             cpb.reducePriv("cap_net_admin+ep");
             cpb.getCredential();
             if(debugMode > 1) cpb.printStatus();
         }catch(const CapabilityException& ex){
             ret = 2;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }catch(...){
             ret = 2;
             cerr << "Error: unandled exception in privilege management." << "\n";
             throw string{"Abort."};
         }

         try{
             if(isServer){
                  NnVpnServer tvpns(cert, key, address, to_string(port), device, psize);
                  tvpns.init();
                  tvpns.start();
             } else {
                  NnVpnClient tvpnc(cert, key, address, to_string(port), device, psize);;
                  tvpnc.init();
                  tvpnc.start();
             }
         }catch(InetException& ex){
             ret = 3;
             cerr << "Error: " << ex.what() << "\n";
             throw string{"Abort."};
         }catch(...){ 
             ret = 1;
             throw string{"Unmanaged Error. Abort."};
         }

    }catch(const string& ex){
        cerr << ex << "\n";
        cout << "Program exits with error(s): check log file.\n";
    }

    return ret;  
}

void printInfo(char* cmd){
      cerr << cmd << " [-f <config_full_path>] [-d level] [-s] | [-h]\n\n";
      cerr << " -f  <full_path> Specify the configuration file path\n";
      cerr << " -d  <dbg_level> set debug mode\n";
      cerr << " -s              set server mode\n";
      cerr << " -h              print this synopsis\n";
      exit(EXIT_FAILURE);
}

