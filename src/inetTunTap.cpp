// -----------------------------------------------------------------
// Inet - networking library
// Copyright (C) 2016-2023  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// -----------------------------------------------------------------

#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <algorithm>
#include <iostream>

#include <inetgeneral.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

namespace inetlib{

using std::copy,
      std::string,
      std::cerr,
      std::to_string,
      inetlib::InetException,
      typeutils::safeSizeRange,
      stringutils::mergeStrings;

Tun::Tun(string dev)  anyexcept
   :  deviceName { dev }
{
    ifreq.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR ;
    copy_n(deviceName.begin(), deviceName.size() >= IFNAMSIZ ? IFNAMSIZ - 1 : deviceName.size(), ifreq.ifr_name);
}

 Tun::~Tun(void) noexcept{
     if(tunfd > 0) close(tunfd);
 }

void Tun::init(void)  anyexcept{
    signal(SIGPIPE, SIG_IGN);
    tunfd = open(cloneDev.c_str(),  O_RDWR | O_CLOEXEC );
    if( tunfd < 0)
        throw( InetException( mergeStrings({ "Error opening TUN cloning device: ", strerror(errno)}) ) );
    if(ioctl(tunfd, TUNSETIFF, reinterpret_cast<void*>(&ifreq)) < 0)
        throw( InetException( mergeStrings({ "Error setting TUNSETIFF on TUN fd: ", strerror(errno)}) ) );

    deviceName = ifreq.ifr_name;
}

const string& Tun::getDeviceName(void)  const noexcept{
    return deviceName;
}

int Tun::getTunFd(void) const noexcept{
     return tunfd;
}

NnVpnClient::NnVpnClient(string pem, string key, string paddr, string pport, string dev, size_t buffSize) anyexcept
   : Tun{dev}, sslClient { pem, key, paddr.c_str(), pport.c_str()}, bufferSize { buffSize }
{ 
    buff.resize(bufferSize);
}

NnVpnClient::~NnVpnClient(void) noexcept
{}

void  NnVpnClient::init(void) anyexcept{
    Tun::init();
    sslClient.init();
}

void  NnVpnClient::start(void) anyexcept{
        int        tunFd  { getTunFd() },
                   sslFd  { sslClient.getFdReader() }; 
        const SSL* cSSL   { sslClient.getHandler().cSSL };
        fd_set     fdsetTun;

        nfdsTun = (tunFd > sslFd) ? tunFd + 1 : sslFd + 1;

        for(;;){
           FD_ZERO(&fdsetTun); 
           FD_SET(tunFd, &fdsetTun);
           FD_SET(sslFd, &fdsetTun);
  
           ssize_t ret {::select(nfdsTun, &fdsetTun, nullptr, nullptr, nullptr)};
           switch(ret){
              [[unlikely]]  case -1:
                 throw InetException("NnVpnClient::start : Select Error.");
              [[unlikely]]  case  0:
                 throw InetException("NnVpnClient::start : Select Timeout.");
              [[likely]]    default:
                  if(FD_ISSET(tunFd, &fdsetTun)) {
                      ssize_t readFromTun { read(tunFd, buff.data(), buff.size()) };
                      switch(readFromTun){
                         break;
                         [[unlikely]]  case 0:
                            throw InetException("NnVpnClient::start : Connection Closed by peer.");
                         break;
                         [[unlikely]]  case -1:
                            throw InetException(mergeStrings({"NnVpnClient::start : TUN Read error: ", strerror(errno)}));
                         [[likely]]    default:
                            ssize_t written { 0 };
                            while( written < readFromTun){
                                int nbytes { sslClient.writeSSLBuffer(buff.data() + written, safeSizeRange<int>(readFromTun - written))};
                                if( nbytes <= 0) {
                                    int errCode { SSL_get_error(cSSL, nbytes) };
                                    switch(errCode){
                                       case SSL_ERROR_WANT_WRITE:
                                       case SSL_ERROR_WANT_ASYNC_JOB:
                                               continue;
                                       default:
                                               throw InetException(mergeStrings({"NnVpnClient::start : writeSSL error : ", to_string(errCode)}));
                                    }
                                }
                                written += nbytes;
                            }
                      }
                  }
                  if(FD_ISSET(sslFd, &fdsetTun)) {
                      ssize_t readFromSsl = sslClient.readSSLBuffer(buff.data(), safeSizeRange<int>(buff.size()));
                      if( readFromSsl <= 0) {
                           int errCode { SSL_get_error(cSSL, readFromSsl) };
                           switch(errCode){
                               case SSL_ERROR_WANT_READ:
                               case SSL_ERROR_WANT_ASYNC_JOB:
                                    continue;
                               default:
                                    throw InetException(mergeStrings({"NnVpnClient::start : readSSL error : ", to_string(errCode)}));
                           }
                      }
                      ssize_t written { 0 };
                      while( written < readFromSsl){
                          ssize_t nbytes { write(tunFd, buff.data() + written, readFromSsl - written) };
                          if( nbytes <= 0) {
                              if (errno == EINTR || errno == EAGAIN) continue;
                              throw InetException(mergeStrings({"NnVpnClient::start : TUN write error : ", strerror(errno)}));
                          }
                          written += nbytes;
                      }
                  }
            }
        }
}

NnVpnServer::NnVpnServer(string pem,   string key, string saddr, string sport, string dev, size_t buffSize) anyexcept
   : Tun{dev}, sslServer { pem, key}, srvAddr { saddr } , srvPort { sport }, bufferSize { buffSize }
{ 
    buff.resize(bufferSize);
}

NnVpnServer::~NnVpnServer(void) noexcept
{}

void  NnVpnServer::init(void) anyexcept{
    Tun::init();
    sslServer.init(srvAddr.c_str(), srvPort.c_str());
}

void  NnVpnServer::start(void) anyexcept{

    sslServer.listen();

    int        tunFd       { getTunFd() };
    fd_set     fdsetTun;

    for(;;){
        try{
           sslServer.accept();
    
           int        sslFd       { sslServer.getFdReader() }; 
           const SSL* cSSL        { sslServer.getHandler().cSSL };
    
           nfdsTun = (tunFd > sslFd) ? tunFd + 1 : sslFd + 1;
    
           for(;;){
               FD_ZERO(&fdsetTun); 
               FD_SET(tunFd, &fdsetTun);
               FD_SET(sslFd, &fdsetTun);
      
               ssize_t ret {::select(nfdsTun, &fdsetTun, nullptr, nullptr, nullptr)};
               switch(ret){
                  [[unlikely]] case -1:
                     throw InetException("NnVpnServer::start : Select Error.");
                  [[unlikely]] case  0:
                     throw InetException("NnVpnServer::start : Select Timeout.");
                  [[likely]]   default:
                      if(FD_ISSET(tunFd, &fdsetTun)) {
                          ssize_t readFromTun { read(tunFd, buff.data(), buff.size()) };
                          switch(readFromTun){
                             [[unlikely]] case 0:
                                throw InetException("NnVpnServer::start : Connection Closed by peer.");
                             break;
                             [[unlikely]] case -1:
                                throw InetException(mergeStrings({"NnVpnServer::start : TUN Read error: ", strerror(errno)}));
                             [[likely]]   default:
                                ssize_t written { 0 };
                                while( written < readFromTun){
                                    int nbytes { sslServer.writeSSLBuffer(buff.data() + written, safeSizeRange<int>(readFromTun - written))};
                                    if( nbytes <= 0) {
                                        int errCode = SSL_get_error(cSSL, nbytes);
                                        switch(errCode){
                                           case SSL_ERROR_WANT_WRITE:
                                           case SSL_ERROR_WANT_ASYNC_JOB:
                                                   continue;
                                           default:
                                                   throw InetException(mergeStrings({"NnVpnServer::start : writeSSL error : ", to_string(errCode)}));
                                        }
                                    }
                                    written += nbytes;
                                }
                          }
                      }
                      if(FD_ISSET(sslFd, &fdsetTun)) {
                          int readFromSsl { sslServer.readSSLBuffer(buff.data(), safeSizeRange<int>(buff.size()))};
                          if( readFromSsl <= 0) {
                               int errCode { SSL_get_error(cSSL, readFromSsl) };
                               switch(errCode){
                                   case SSL_ERROR_WANT_READ:
                                   case SSL_ERROR_WANT_ASYNC_JOB:
                                        continue;
                                   case SSL_ERROR_SYSCALL:
                                        throw InetException(mergeStrings({"NnVpnServer::start : readSSL error : ", to_string(errCode), " : suberror : ", strerror(errno)}));
                                   default:
                                        throw InetException(mergeStrings({"NnVpnServer::start : readSSL error : ", to_string(errCode)}));
                               }
                          }
                          ssize_t written { 0 };
                          while( written < readFromSsl){
                               ssize_t nbytes { write(tunFd, buff.data() + written, safeSizeRange<int>(readFromSsl - written))};
                               if( nbytes <= 0) {
                                  if (errno == EINTR || errno == EAGAIN) continue;
                                  throw InetException(mergeStrings({"NnVpnServer::start : TUN write error : ", strerror(errno)}));
                               }
                               written += nbytes;
                          }
                      }
                }
            }
        } catch(InetException& ex){
               cerr << mergeStrings({ "NnVpnServer::start() : Caught Exception : ", ex.what(), " -> restart loop\n" });
        }

        sslServer.disconnect();
    }
}

} // End namespace