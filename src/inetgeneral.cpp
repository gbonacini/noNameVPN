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

#include <openssl/err.h> 

#include <inetgeneral.hpp>

#include <Types.hpp>
#include <StringUtils.hpp>

namespace inetlib{

    using std::string,
          std::vector,
          std::fill,
          std::copy,
          conceptsLib::Appendable,
          stringutils::mergeStrings,
          typeutils::safeSizeRange,
          typeutils::safeSizeT;

    InetException::InetException(int errNum)
     : errorMessage{"None"}, errorCode{errNum}
    {}

    InetException::InetException(string& errString)
       : errorMessage{errString}, errorCode{0}
    {}

    InetException::InetException(string&& errString)
       : errorMessage{std::move(errString)}, errorCode{0}
    {}

    InetException::InetException(int errNum, string errString)
       : errorMessage{errString}, errorCode{errNum}
    {}

    const char* InetException::what(void) const noexcept{
       return errorMessage.c_str();
    }

    int  InetException::getErrorCode(void)  const noexcept{
       return errorCode;
    }

    Inet::Inet(readFunc rFx, writeFunc wFx) 
    {
        hints.ai_socktype       = SOCK_STREAM;
        hints.ai_family         = AF_INET;
        hints.ai_flags          = AI_NUMERICSERV ;
   
        rFunc                   = rFx != nullptr ? rFx : readSocket;
        wFunc                   = wFx != nullptr ? wFx : writeSocket;
    }

	 Inet::~Inet(){}

    ssize_t Inet::readBuffer(size_t len, Handler* hdlr, void** buff) anyexcept{
        void**  localBuff       { nullptr };
        void*   indBuff         { nullptr };
        Handler *localHandler   { hdlr ? hdlr : &handler };
        size_t  bufLen          { len ? len : buffer.size() };
        if(hdlr != nullptr){
           localBuff            = buff;
        }else{
           indBuff              = buffer.data();
           localBuff            = &indBuff;
        }
     
        fill(static_cast<char*>(*localBuff), static_cast<char*>(*localBuff) + bufLen, 0);
        readLen = (*rFunc)(localHandler, *localBuff, bufLen);
        if(readLen == 0)                  throw InetException("Connection was closed by the server.");
        if(readLen < 0 && errno != EINTR) throw InetException(mergeStrings({"readBuffer: Read error: ", strerror(errno)}));
  
        return readLen > 0 ? readLen : 0;
    }

	 ssize_t Inet::readBufferNb(size_t len, Handler* hdlr, void** buff) anyexcept{
        void**  localBuff       { nullptr };
        void*   indBuff         { nullptr };
        Handler *localHandler   { hdlr ? hdlr : &handler};
        size_t bufLen           { len  ? len  : buffer.size()};
        if(hdlr != nullptr){
           localBuff            = buff;
        }else{
           indBuff              = buffer.data();
           localBuff            = &indBuff;
        }
   
        fill(static_cast<char*>(*localBuff), static_cast<char*>(*localBuff) + bufLen, 0);
        ssize_t tlen         { (*rFunc)(localHandler, *localBuff, bufLen) };
        if(tlen == 0) throw InetException("Connection was closed by the server.");
        if(tlen < 1 && errno != EAGAIN && errno != EINTR)
                      throw InetException(mergeStrings({"readBufferNb: Read error: ", strerror(errno)}));
  
        readLen              = tlen > 0 ? tlen : 0;
     
        return readLen;
    }

    size_t Inet::readLine(Handler* hdlr) anyexcept{
        char     buff[2]        {0,0};
        Handler  *localHandler  { hdlr ? hdlr : &handler};
        currentLine             = "";

        for(;;){
           ssize_t ret { (*rFunc)(localHandler, buff, 1) };
           switch(ret){
              [[likely]]   case 1:
                 currentLine.append(static_cast<const char*>(buff));
                 if(buff[0] == separator) return currentLine.size();
                 if(sizeMax > 0 && currentLine.size() == (sizeMax + 1))
                    throw InetException("readLine: Line too long.");
              break;
              [[unlikely]] case 0:
                 throw InetException("readLine: Connection Closed by peer.");
              [[unlikely]] default:
                 throw InetException(mergeStrings({"readLine: Read error: ", strerror(errno)}));
           }
        }
    }

    size_t Inet::readLineTimeout(Handler *hdlr) anyexcept{
        char     buff[2]        {0,0} ;
        Handler  *localHandler  { hdlr ? hdlr : &handler};
        fd_set   fdset;

        currentLine             = "";

        for(;;){
           FD_ZERO(&fdset); 
           FD_SET(*(localHandler->peerFd), &fdset);
  
           if(*(localHandler->peerFd) > nfds)
              nfds = *(localHandler->peerFd) + 1;
  
           ssize_t ret {::select(nfds, &fdset, nullptr, nullptr, &tvMin)};
           switch(ret){
              [[unlikely]] case -1:
                 throw InetException("readLineTimeout: Select Error.");
              [[unlikely]] case  0:
                 throw InetException("readLineTimeout: Select Timeout.");
              [[likely]]   default:
                 ret = (*rFunc)(localHandler, buff, 1UL);
                 switch(ret){
                    [[likely]]   case 1:
                       currentLine.append(static_cast<const char*>(buff));
                       if(buff[0] == separator) return currentLine.size();
                       if(sizeMax > 0 && currentLine.size() == (sizeMax + 1))
                          throw InetException("readLine: Line too long.");
                    break;
                    [[unlikely]] case 0:
                       throw InetException("readLineTimeout: Connection Closed by peer.");
                    [[unlikely]] default:
                       throw InetException(mergeStrings({"readLineTimeout: Read error: ", strerror(errno)}));
                 }
            }
        }
    }

    int Inet::readLineTimeoutNoErr(Handler* hdlr, bool noEagain) anyexcept {
                char     buff[2] {0,0};
                Handler  *localHandler = hdlr ? hdlr : &handler;
                fd_set   fdset;

                currentLine="";

                FD_ZERO(&fdset); 
                FD_SET(*(localHandler->peerFd), &fdset);
                for(;;){
                      if(*(localHandler->peerFd) > nfds) nfds=*(localHandler->peerFd) + 1;
                      errno = 0;                  
                      int ret=::select(nfds, &fdset, nullptr, nullptr, &tvMax);
                      switch(ret){
                           [[unlikely]] case -1:
                                 throw InetException("Select Error.");
                           [[unlikely]] case  0:
                                 FD_CLR(*(localHandler->peerFd), &fdset);
                                 return 0;
                           [[likely]] default:
                                 ret = (*rFunc)(localHandler, buff, 1UL); 
                                 switch(ret){
                                       [[likely]]   case 1:
                                             currentLine.append((const char* )buff);
                                             if(buff[0] == separator){
                                                  FD_CLR(*(localHandler->peerFd),  &fdset);
                                                  return 1;
                                             }
                                       break;
                                       [[unlikely]] case 0:
                                             FD_CLR(*(localHandler->peerFd),  &fdset);
                                             return 0;
                                       break;
                                       [[unlikely]] default:
                                             if(noEagain && errno == EAGAIN) continue;
                                             FD_CLR(*(localHandler->peerFd),  &fdset);
                                             throw InetException(mergeStrings({"Read error: ", strerror(errno)}));
                                 }
                      }
                }
    }

    void Inet::setBlocking(bool onOff) anyexcept{
        if( socketFd != -1){
           int oFlags         { fcntl(socketFd, F_GETFL) };
           if(oFlags == -1) 
              throw InetException("setBlocking: Error getting descriptor settings.");
           int nFlags         { onOff ? oFlags | O_NONBLOCK : oFlags & ~O_NONBLOCK };
           if(fcntl(socketFd, F_SETFL, nFlags) == -1)
              throw InetException("setBlocking: Error setting descriptor settings.");
        }else{
           throw InetException("setBlocking: Error trying socketFd() on an invalid descriptor.");
        } 
    }

    void Inet::writeBuffer(const uint8_t* msg, size_t size, Handler* hdlr) const anyexcept{
        Handler  *localHandler   { hdlr ? hdlr : &handler };
   
        for(size_t pldr{0}; pldr < size;){
           ssize_t writeLen   { (*wFunc)(localHandler, 
                                reinterpret_cast<void*>(const_cast<uint8_t*>(msg + pldr)), 
                                safeSizeRange<size_t>(size - pldr)) }; 
           if(writeLen < 0 && errno != EINTR) 
               throw InetException(mergeStrings({"writeBuffer: Write error: ", strerror(errno)}));

           if(writeLen > 0){
              pldr    += safeSizeT(writeLen); 
              msg     += safeSizeT(writeLen);
           }
        }
    }
   
    void Inet::writeBuffer(const string& msg, Handler* hdlr) const anyexcept{
       ssize_t msgLen           { safeSizeRange<ssize_t>(msg.size()) };
       Handler *localHandler    { hdlr ? hdlr : &handler };
    
       for(ssize_t s{0}; s < safeSizeRange<int>(msg.size());){
          ssize_t writeLen { (*wFunc)(localHandler, 
                             reinterpret_cast<void*>(const_cast<char*>(msg.c_str() + s)),
                             safeSizeRange<size_t>(msgLen - s)) };
          if(writeLen < 0 && errno != EINTR) 
             throw InetException(mergeStrings({"Write error: ", strerror(errno)}));
          if(writeLen > 0) s += writeLen;
       }
    }

	 ssize_t Inet::readSocket(Handler* fDesc, void *buf, size_t len) noexcept{
       if(len > 0) return ::read(*(static_cast<int const *>(fDesc->peerFd)), buf, len);
       else        return EINVAL;
    }
   
    ssize_t Inet::writeSocket(Handler* fDesc, void *buf, size_t len) noexcept{
       if(len > 0) return ::write(*(static_cast<int const *>(fDesc->peerFd)), buf, len);
       else        return EINVAL;
    }

	 bool Inet::checkHeader(string header, bool read, 
                          bool timeout, Handler *hdlr) anyexcept
	 {
       if(read) timeout?(void)readLineTimeout(hdlr) : (void)readLine(hdlr);

       return currentLine.find(header) != string::npos ? true : false; 
    }

	 bool Inet::checkHeaderBegin(string header, bool read, 
                          bool timeout, Handler *hdlr) anyexcept
	 {
       if(read) timeout?(void)readLineTimeout(hdlr) : (void)readLine(hdlr);

       return currentLine.find(header) == 0 ? true : false; 
    }

    bool Inet::tryCheckHeader(string header, Handler *hdlr) anyexcept{
       readLineTimeoutNoErr(hdlr, true);
       
       return currentLine.find(header) != string::npos ? true : false; 
    }

    bool Inet::checkHeaderRaw(string header) const anyexcept{
        try{
           string temp; 
           temp.insert(temp.end(), buffer.begin(), buffer.end());
           return temp.find(header) != string::npos ? true : false;
        }catch (...){
           throw InetException("checkHeaderRaw: Unexpected data error.");
        }
    }

    void Inet::addToCurrentLine(string* dest) const noexcept{
         dest->append(currentLine);
    }

    const string& Inet::getCurrentLine(void) const noexcept{
         return currentLine;
    }

    void  Inet::getReceivedData(std::vector<uint8_t>& dest) const anyexcept{
       if(readLen < 1) throw InetException("getReceivedData: no data to copy.");

       try{
            copy(buffer.begin(), buffer.begin() + readLen, dest.begin());
       } catch(...){
            throw InetException("getReceivedData: can't copy to destination.");
       }
    }

    ssize_t Inet::getReadLen(void) const noexcept{
        return readLen;
    }

    ssize_t Inet::getLineLen(void) const noexcept{
        return safeSizeRange<ssize_t>(currentLine.size()); 
    }

    const Handler& Inet::getHandler(void)  const noexcept{
         return handler;
    }

    int Inet::getSocketFd(void) noexcept{
         return socketFd;
    } 

	 void Inet::initBuffer(size_t len) anyexcept{
        if(len == 0) throw InetException("initBuffer: InitBuffer: Invalid buffer size");
      
        try{
           buffer.resize(len);
           bufferPtr         = buffer.data();
        }catch(...){
           throw InetException("InitBuffer: Can't initialize buffer.");
        }
    }

	 void Inet::getBufferCopy(Appendable auto& dest, bool append)  const anyexcept {
       if(buffer.size() == 0)
          throw InetException("getBufferCopy: Attempt of copy an unitialized buffer.");
       try{
          if(!append) dest.clear();
          dest.insert(dest.end(), buffer.begin(), buffer.begin() + readLen);
       }catch(...){
          throw InetException("getBufferCopy: Attempt of copy Inet buffer failed.");
       }
    }

	 void Inet::setTimeoutMin(long int seconds, int useconds) noexcept{
       tvMin.tv_sec            = seconds;
       tvMin.tv_usec           = useconds;
    }
   
    void Inet::setTimeoutMax(long int seconds, int useconds) noexcept{
       tvMax.tv_sec            = seconds;
       tvMax.tv_usec           = useconds;
    }

    void Inet::setReadFunc( readFunc rFx ) noexcept{
        rFunc = rFx;
    }

    void Inet::setWriteFunc( writeFunc wFx ) noexcept{
        wFunc = wFx;
    }

    void Inet::setSeparator(char sp)  noexcept{
        separator = sp;
    }

    void Inet::setSizeMax(size_t sz)  noexcept{
        sizeMax = sz;
    }

    bool Inet::checkMultipleHeader(string header, Handler *hdlr ) anyexcept {
         while(readLineTimeoutNoErr(hdlr)) if(currentLine.starts_with(header)) return false;
         
         return true;
    }

    #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wundefined-func-template"
    #endif

    template void Inet::getBufferCopy(string& dest, bool append=false)           const anyexcept;
    template void Inet::getBufferCopy(vector<uint8_t>& dest, bool append=false)  const anyexcept;

    #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
    #pragma clang diagnostic pop
    #endif

    InetSSL::InetSSL(string cert, string key)
	    :  SSLcertificate{cert}, SSLkey{key}
	 {
        SSL_library_init();
        SSL_load_error_strings();
    }

    InetSSL::~InetSSL(void) noexcept {
         ERR_free_strings();
         EVP_cleanup();
    }

    ssize_t InetSSL::writeSSL(Handler* sslFd, void* buffer, size_t bufferLen){
         return( ::SSL_write(sslFd->cSSL, buffer, safeSizeRange<int>(bufferLen))); 
    }

    ssize_t InetSSL::readSSL(Handler* sslFd, void* buffer, size_t bufferLen){
         return( ::SSL_read(sslFd->cSSL, buffer, safeSizeRange<int>(bufferLen))); 
    }
} // End namespace
