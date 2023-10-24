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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>

#include <inetgeneral.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

namespace inetlib{
    using std::string,
          typeutils::safeSizeRange,
	      stringutils::mergeStrings;

    InetClient::InetClient(const char* ifc, const char* prt, 
	                       readFunc rFx, writeFunc wFx) anyexcept
	   :  Inet(rFx, wFx), addr{ifc}, port{prt}
	{}

    InetClient::InetClient(const string& ifc, const string& prt, 
	                       readFunc rFx, writeFunc wFx) anyexcept
	   : Inet(rFx, wFx), addr{ifc}, port{prt}
	{}

    void InetClient::init(void){
        if(int errCode { getaddrinfo(addr.c_str(), port.c_str(), &hints, &result) }; errCode != 0)
            throw InetException(mergeStrings({"Getaddrinfo Error: ", ::gai_strerror(errCode)}));
        
        for(resElement=result; resElement!=nullptr; resElement=resElement->ai_next){
            socketFd=socket(resElement->ai_family, resElement->ai_socktype, resElement->ai_protocol);
            if(socketFd == -1) continue;

            if(connect(socketFd,resElement->ai_addr, resElement->ai_addrlen) == 0)
                break;
        }

        if(resElement == nullptr) throw InetException("Connect socket to any address failed.");

        (void)freeaddrinfo(result);
        result         = nullptr;
        handler.peerFd = &socketFd;
	}

    void InetClient::cleanResurces(void) noexcept{
        if(socketFd >= 0 ){
            close(socketFd);
            socketFd=-1;
        }
        if(result != nullptr){
            (void)freeaddrinfo(result);
            result=nullptr;
        }
        handler.peerFd = nullptr;
    }

    InetClient::~InetClient(void) noexcept {
        cleanResurces();
    }
    
    InetClientSSL::InetClientSSL(string cert, string key,
                                 const char* ifc, const char* port, 
	                             readFunc rFx, writeFunc wFx) anyexcept
       : InetClient(ifc, port, rFx, wFx),
         InetSSL(cert, key)
    {}

    void InetClientSSL::init(void) anyexcept{
        InetClient::init();

        OpenSSL_add_all_algorithms();

        InetSSL::sslctx = SSL_CTX_new( SSLv23_client_method());
        SSL_CTX_set_options(InetSSL::sslctx, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_use_certificate_file(InetSSL::sslctx, SSLcertificate.c_str(), SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(InetSSL::sslctx, SSLkey.c_str(), SSL_FILETYPE_PEM);
        handler.cSSL = SSL_new(InetSSL::sslctx);
        
        SSL_set_fd(handler.cSSL, *(handler.peerFd));
        if(SSL_connect(handler.cSSL) <= 0)
             throw InetException("SSL connect error.");
	}

    void InetClientSSL::cleanResurces(void) noexcept{
        if(socketFd >= 0 ){
            close(socketFd);
            socketFd=-1;
        }

        if(result != nullptr){
            (void)freeaddrinfo(result);
            result=nullptr;
        }
        if(handler.cSSL != nullptr){
            SSL_shutdown(handler.cSSL);
            SSL_free(handler.cSSL);
            handler.cSSL   = nullptr;
            handler.peerFd = nullptr; 
        }
    }

    InetClientSSL::~InetClientSSL(void) noexcept {
        cleanResurces();
    }

    int InetClientSSL::writeSSLBuffer(const char* buffer, int bufferLen) noexcept{
        return( ::SSL_write(handler.cSSL, reinterpret_cast<const void*>(buffer), bufferLen));
    }

    int InetClientSSL::writeSSLBuffer(string buffer) noexcept{
        return( ::SSL_write(handler.cSSL, reinterpret_cast<const void*>(buffer.c_str()), safeSizeRange<int>(buffer.length())));
    }

    int InetClientSSL::readSSLBuffer(char* buffer, int bufferLen) noexcept{
        return( ::SSL_read(handler.cSSL, reinterpret_cast<void*>(buffer), bufferLen));
    }

    int  InetClientSSL::getFdReader(void)  anyexcept{
        int fd { SSL_get_rfd(handler.cSSL) };
        if(fd == -1)  throw InetException("InetClientSSL::getReaderFd : error");
        return fd;    
    }

    int  InetClientSSL::getFdWriter(void)  anyexcept{
        int fd { SSL_get_wfd(handler.cSSL) };
        if(fd == -1)  throw InetException("InetClientSSL::getReaderFd : error");
        return fd;    
    }

} // End Namespace
