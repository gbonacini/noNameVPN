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

#include <inetgeneral.hpp>
#include <StringUtils.hpp>
#include <Types.hpp>

namespace inetlib{

    using std::string,
          std::to_string,
          typeutils::safeSizeRange,
	      stringutils::mergeStrings;

    InetServer::InetServer(readFunc  rFx, writeFunc wFx)  
	    : Inet::Inet(rFx, wFx)
	{
        hints.ai_flags         = hints.ai_flags | AI_PASSIVE;
    }

    InetServer::~InetServer(void) noexcept {
        cleanResurces();
    }

    void InetServer::cleanResurces(void) noexcept{
        if(Inet::socketFd >= 0 ) close(Inet::socketFd);
        if(result != nullptr){
            (void)freeaddrinfo(result);
            result=nullptr;
        }
    }

    void InetServer::init(const char* ifc, const char* port) anyexcept {
        if( int errCode { getaddrinfo(ifc, port, &hints, &result) }; errCode != 0)
            throw InetException(mergeStrings({"Getaddrinfo Error: ", ::gai_strerror(errCode)}));
        
        for(resElement=result; resElement!=nullptr; resElement=resElement->ai_next){
            Inet::socketFd = socket(resElement->ai_family, resElement->ai_socktype, resElement->ai_protocol);
            if(Inet::socketFd == -1) continue;

            if(int activate  { 1 } ; setsockopt(Inet::socketFd, SOL_SOCKET, SO_REUSEADDR, &activate, sizeof(activate)) == -1){
                cleanResurces();
                throw InetException(mergeStrings({"Setsockopt Error : ", strerror(errno)}));
            }
        
            if(::bind(Inet::socketFd, resElement->ai_addr, resElement->ai_addrlen) == 0) break;
        }

        if(resElement == nullptr) throw InetException("InetServer init() fail: getaddrinfo() with no result.");

        if(result != nullptr){
            (void)freeaddrinfo(result);
            result=nullptr;
        }
    }

    void InetServer::listen(int backLogQueueLen) const anyexcept {
        if(::listen(Inet::socketFd, backLogQueueLen) == -1)
            throw InetException(mergeStrings({"Listen Error : ", strerror(errno)}));
    }

    void InetServer::setTimeoutReadVal(long int sec, long int msec) anyexcept {
        timeoutRead.tv_sec        = sec;
        timeoutRead.tv_usec       = msec;
    }

    void InetServer::setTimeoutWriteVal(long int sec, long int msec) anyexcept {
        timeoutWrite.tv_sec        = sec;
        timeoutWrite.tv_usec       = msec;
    }

    void InetServer::accept(void) anyexcept {
        acceptFd=::accept(Inet::socketFd, &addressIn, &InetServer::addressLen);
        if(acceptFd == -1) throw InetException(mergeStrings({"Accept Error : ", strerror(errno)}));

        if(timeoutRead.tv_sec != 0 || timeoutRead.tv_usec != 0){
            if (setsockopt (acceptFd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeoutRead), sizeof(timeoutRead)) < 0)
            throw InetException(mergeStrings({"Set Timeout Error : ", strerror(errno)}));
        }
        if(timeoutWrite.tv_sec != 0 || timeoutWrite.tv_usec != 0){
            if (setsockopt (acceptFd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeoutWrite), sizeof(timeoutWrite)) < 0)
            throw InetException(mergeStrings({"Set Timeout Error : ", strerror(errno)}));
        }

        handler.peerFd=&acceptFd;
    }

    void InetServer::disconnect(void) anyexcept {
        if(acceptFd >= 0){
            close(acceptFd);
            acceptFd = -1;
        }else{
            throw InetException("Tried to Close an Invalid Accept Fd.");
        }

        handler.peerFd = nullptr;
    }

    InetServerSSL::InetServerSSL(string cert, string key) anyexcept 
      : InetSSL(cert, key)
    {
        if(access(cert.c_str(), R_OK) != 0) throw InetException(mergeStrings({"InetServerSSL : Certificate File Access : ", strerror(errno)}));
        if(access(key.c_str(),  R_OK) != 0) throw InetException(mergeStrings({"InetServerSSL : Key File Access : ", strerror(errno)}));
        
        setReadFunc( InetSSL::readSSL );
        setWriteFunc( InetSSL::writeSSL );

        OpenSSL_add_all_algorithms();
        InetSSL::sslctx = SSL_CTX_new( SSLv23_server_method());
        SSL_CTX_set_options(InetSSL::sslctx, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_use_certificate_file(InetSSL::sslctx, SSLcertificate.c_str(), SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(InetSSL::sslctx, SSLkey.c_str(), SSL_FILETYPE_PEM);
    }

    InetServerSSL::~InetServerSSL() noexcept {
        cleanResurces();
    }

    void InetServerSSL::cleanResurces(void) noexcept{
        disconnect();

        if(handler.peerFd != nullptr){ 
            if(*(handler.peerFd) >= 0 ){
                close(*(handler.peerFd));
                *(handler.peerFd) = -1;
            }
        }
    }

    void InetServerSSL::accept(void) anyexcept {
        acceptFd=::accept(Inet::socketFd, &addressIn, &InetServer::addressLen);
        if(acceptFd == -1){
            throw InetException(mergeStrings({"Accept Error : ", strerror(errno)}));
        }
        if(timeoutRead.tv_sec != 0 || timeoutRead.tv_usec != 0){
            if (setsockopt (acceptFd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const void*>(&timeoutRead), sizeof(timeoutRead)) < 0)
            throw InetException(mergeStrings({"Set Timeout Error : ", strerror(errno)}));
        }
        if(timeoutWrite.tv_sec != 0 || timeoutWrite.tv_usec != 0){
            if (setsockopt (acceptFd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const void*>(&timeoutWrite), sizeof(timeoutWrite)) < 0)
            throw InetException(mergeStrings({"Set Timeout Error : ", strerror(errno)}));
        }
        handler.peerFd = &acceptFd;
        handler.cSSL   = SSL_new(InetSSL::sslctx);

        SSL_set_fd(handler.cSSL, *(handler.peerFd));
        bool isAccepted { false };
        while(!isAccepted){
            int aRet { SSL_accept(handler.cSSL) };
            switch (aRet) {
                case 1:
                    isAccepted = true;
                break;
                case 0:
                    throw InetException("InetServerSSL::accept : Connection Closed by peer.");
                default:
                    int errCode { SSL_get_error(handler.cSSL, aRet) };
                    switch(errCode){
                            case SSL_ERROR_WANT_WRITE:
                            case SSL_ERROR_WANT_ASYNC_JOB:
                                 continue;
                            default:
                                 throw InetException(mergeStrings({"InetServerSSL::accept : SSL_connect error : ", to_string(errCode)}));
                    }
            }
        }
    }

    void InetServerSSL::disconnect(void) anyexcept {
        if(handler.cSSL != nullptr){
                SSL_shutdown(handler.cSSL);
                SSL_free(handler.cSSL);
                handler.cSSL = nullptr;
        }
    }

    int InetServerSSL::writeSSLBuffer(const char* buffer, int bufferLen) noexcept{
        return( ::SSL_write(handler.cSSL, reinterpret_cast<const void*>(buffer), bufferLen));
    }

    int InetServerSSL::writeSSLBuffer(string buffer) noexcept{
        return( ::SSL_write(handler.cSSL, reinterpret_cast<const void*>(buffer.c_str()), safeSizeRange<int>(buffer.length()))); 
    }

    int InetServerSSL::readSSLBuffer(char* buffer, int bufferLen) noexcept{
        return( ::SSL_read(handler.cSSL, reinterpret_cast<void*>(buffer), bufferLen));
    }

    int InetServerSSL::writeSSLBuffer(const Handler* ctx, const char* buffer, int bufferLen) noexcept{
        return( ::SSL_write(ctx->cSSL, reinterpret_cast<const void*>(buffer), bufferLen));
    }

    int InetServerSSL::writeSSLBuffer(const Handler* ctx, string buffer) noexcept{
        return( ::SSL_write(ctx->cSSL, reinterpret_cast<const void*>(buffer.c_str()), safeSizeRange<int>(buffer.length()))); 
    }

    int InetServerSSL::readSSLBuffer(const Handler* ctx, char* buffer, int bufferLen) noexcept{
        return( ::SSL_read(ctx->cSSL, reinterpret_cast<void*>(buffer), bufferLen));
    }

    int  InetServerSSL::getFdReader(void)  anyexcept{
        int fd { SSL_get_rfd(handler.cSSL) };
        if(fd == -1)  throw InetException("InetClientSSL::getReaderFd : error");
        return fd;    
    }

    int  InetServerSSL::getFdWriter(void)  anyexcept{
        int fd { SSL_get_wfd(handler.cSSL) };
        if(fd == -1)  throw InetException("InetClientSSL::getReaderFd : error");
        return fd;    
    }

} // End namespace
