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

#pragma once

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <resolv.h>
#include <fcntl.h>

#include <openssl/ssl.h> 

#include <linux/if.h>
#include <linux/if_tun.h>

#include <vector> 
#include <string>
#include <cstddef>
#include <cerrno>

#include <anyexcept.hpp>
#include <ConceptsLib.hpp>
#include <debug.hpp>

namespace inetlib {

    using Addrinfo=struct addrinfo;
    using Timeval=struct timeval;
	using Sockaddr=struct sockaddr;
	using SockaddrIn=struct sockaddr_in;
    using Addrinfo=struct addrinfo;
    using Hostent=struct hostent;
    using Ifreq=struct  ifreq;

    enum ERR_CODES { ACCEPT_ERROR=255, INVALID_ALLOCATION=999 };

    class InetException final : public std::exception {
      public:
         explicit    InetException(int errNum);
         explicit    InetException(std::string&  errString);
         explicit    InetException(std::string&& errString);
                     InetException(int errNum, std::string errString);
         const char* what(void)                                        const noexcept override;
         int         getErrorCode(void)                                const noexcept;

      private:
         std::string errorMessage;
         int         errorCode;
    };

    struct Handler{
        int            *peerFd;
        SockaddrIn     *sockaddrin;
        unsigned int   addrLen;
        SSL            *cSSL;
    };

	typedef ssize_t ( *readFunc)  ( Handler*, void*, size_t );
    typedef ssize_t ( *writeFunc) ( Handler*, void*, size_t );

    class Inet{
      public:
         explicit Inet(readFunc rFx=nullptr, writeFunc wFx=nullptr);
         virtual  ~Inet(void);

         ssize_t  readBuffer(size_t len=0, Handler* hdlr=nullptr, 
                             void** buff=nullptr)                           anyexcept;
         ssize_t  readBufferNb(size_t len=0, Handler* hdlr=nullptr, 
                             void** buff=nullptr)                           anyexcept;
         size_t   readLine(Handler* hdlr=nullptr)                           anyexcept;
         size_t   readLineTimeout(Handler* hdlr=nullptr)                    anyexcept;
         int      readLineTimeoutNoErr(Handler* hdlr=nullptr,
                                       bool noEagain=false)                 anyexcept;
         void     setBlocking(bool onOff=true)                              anyexcept;
   
         void     writeBuffer(const uint8_t* msg, size_t size, 
                              Handler* hdlr=nullptr)                  const anyexcept;
         void     writeBuffer(const std::string& msg, 
                              Handler* hdlr=nullptr)                  const anyexcept;
         static 
         ssize_t  readSocket(Handler* fDesc, 
                             void *buf,  size_t len)                        noexcept; 
         static
         ssize_t  writeSocket(Handler* fDesc, 
                              void *buf, size_t len)                        noexcept;
   
         bool     checkHeader(std::string header,          
                              bool read=false, 
                              bool timeout=false, 
                              Handler *hdlr=nullptr)                        anyexcept;
         bool     checkHeaderBegin(std::string header,     
                               bool read=false, 
                              bool timeout=false, 
                              Handler *hdlr=nullptr)                        anyexcept;
         bool     tryCheckHeader(std::string header,
                              Handler *hdlr=nullptr)                        anyexcept;
         bool     checkHeaderRaw(std::string header)                  const anyexcept;
         bool     checkMultipleHeader(std::string header, 
                                      Handler* hdlr=nullptr)                anyexcept;
   
         void     addToCurrentLine(std::string* dest)                 const noexcept; 
         void     getReceivedData(std::vector<uint8_t>& dest)         const anyexcept;
         const std::string&
                  getCurrentLine(void)                                const noexcept;
         ssize_t  getReadLen(void)                                    const noexcept;
         ssize_t  getLineLen(void)                                    const noexcept;
         const Handler&
                  getHandler(void)                                    const noexcept;
         static
         int      getSocketFd(void)                                         noexcept;
         void     initBuffer(size_t len)                                    anyexcept;
         void     getBufferCopy(conceptsLib::Appendable auto& dest, 
                                bool append=false)                    const anyexcept;
   
         void     setTimeoutMin(long int seconds, int useconds=0)           noexcept;
         void     setTimeoutMax(long int seconds, int useconds=0)           noexcept;
         void     setReadFunc(readFunc rFx )                                noexcept;
         void     setWriteFunc(writeFunc wFx )                              noexcept;
         void     setSeparator(char sp='\n')                                noexcept;
         void     setSizeMax(size_t sz=0)                                   noexcept;

      protected:
         static   inline int socketFd       { -1 };
         mutable  Handler    handler        {};
         ssize_t             readLen        { 0 };
         Addrinfo            hints          {},
                             *result        { nullptr }, 
                             *resElement    { nullptr };
   
         void*                 bufferPtr    { nullptr };
         std::vector<uint8_t>  buffer;
         std::string           currentLine;
         readFunc              rFunc;
         writeFunc             wFunc;
         char                  separator    {'\n'};
         size_t                sizeMax      { 0 } ;

      private:
         Timeval               tvMin        { 3,0 },
                               tvMax        { 10,0 };
         int                   nfds         { -1 };    
    };

    class InetClient : public Inet{
        public:
            InetClient(const char* ifc, const char* prt,
			          readFunc  rFx=nullptr,
					  writeFunc wFx=nullptr)                                  anyexcept;
            InetClient(const std::string& ifc, const std::string& prt,
			          readFunc  rFx=nullptr, 
					  writeFunc wFx=nullptr)                                  anyexcept;
            ~InetClient(void)                                                 noexcept;
			void init(void)                                                   anyexcept;
			
        private:
		    const std::string addr,
			                  port;

            void cleanResurces(void)                                          noexcept;
    };

    class InetServer : public Inet{
        public:
            explicit InetServer(readFunc  rFx=Inet::readSocket, 
					            writeFunc wFx=Inet::writeSocket)               anyexcept;
            virtual        ~InetServer(void)                                   noexcept;
            void           init(const char* ifc, const char* port)             anyexcept;
            void           listen(int backLogQueueLen=50) const                anyexcept;
            virtual void   accept(void)                                        anyexcept;
            void           disconnect(void)                                    anyexcept;
            void           setTimeoutReadVal(long int sec, long int msec=0)    anyexcept;
            void           setTimeoutWriteVal(long int sec, long int msec=0)   anyexcept;

        protected:
            int                      acceptFd      { -1 };
            static inline socklen_t  addressLen    { sizeof(Sockaddr) };
            Sockaddr                 addressIn;
            static inline Timeval    timeoutRead   { 3,0 };
            static inline Timeval    timeoutWrite  { 3,0 }; 

        private:
            void         cleanResurces(void)                                  noexcept;
    };

    class InetSSL{
        public:
            InetSSL(std::string cert, std::string key);
            ~InetSSL(void)                                                   noexcept;

        protected:

            static ssize_t writeSSL(Handler* sslFd, void* buffer, size_t bufferLen);
            static ssize_t readSSL(Handler* sslFd, void* buffer, size_t bufferLen);

            std::string    SSLcertificate,
                           SSLkey;
            static inline  SSL_CTX* sslctx { nullptr };
    };

    class InetClientSSL : public InetClient, public InetSSL {
        public:
            InetClientSSL(std::string cert, std::string key,
                          const char* ifc, const char* port,
			              readFunc rFx  = InetSSL::readSSL, 
					      writeFunc wFx = InetSSL::writeSSL)               anyexcept;
            ~InetClientSSL(void)                                           noexcept;

			void init(void)                                                anyexcept;

            int  writeSSLBuffer(const char* buffer, int bufferLen)         noexcept;
            int  writeSSLBuffer(std::string buffer)                        noexcept;
            int  readSSLBuffer(char* buffer, int bufferLen)                noexcept;

            int  getFdReader(void)                                         anyexcept;
            int  getFdWriter(void)                                         anyexcept;

        private:
            void cleanResurces(void)                                       noexcept;
    };

    class InetServerSSL : public InetServer, public InetSSL {
        public:
            InetServerSSL(std::string cert, std::string key)               anyexcept;
            virtual      ~InetServerSSL(void)                              noexcept;
            virtual void accept(void)                                      anyexcept  override;
            void         disconnect(void)                                  anyexcept;
 
            int writeSSLBuffer(const char* buffer, int bufferLen)          noexcept;
            int writeSSLBuffer(std::string buffer)                         noexcept;
            int readSSLBuffer(char* buffer, int bufferLen)                 noexcept;
 
            static int writeSSLBuffer(const Handler* ctx, const char* buffer, 
                                      int bufferLen)                       noexcept;
            static int writeSSLBuffer(const Handler* ctx, 
                                      std::string buffer)                  noexcept;
            static int readSSLBuffer(const Handler* ctx, char* buffer, 
                                     int bufferLen)                        noexcept;
            int        getFdReader(void)                                   anyexcept;
            int        getFdWriter(void)                                   anyexcept;

        private:
            void cleanResurces(void)                                       noexcept;
    };

    class Tun{
        private:
            static const inline std::string cloneDev   {"/dev/net/tun"};
            std::string                     deviceName { "" };
            Ifreq                           ifreq      {};
            int                             tunfd      { -1 };
    
        public:
            explicit Tun(std::string dev)                                  anyexcept;                
            ~Tun(void)                                                     noexcept;
            void                   init(std::string tunIpString, 
                                        std::string tunMaskString)         anyexcept;
            const std::string&     getDeviceName(void)     const           noexcept;
            int                    getTunFd(void)          const           noexcept;
    };
    
    class NnVpnClient : public Tun{
        private:
            InetClientSSL           sslClient;
            size_t                  bufferSize;
            int                     nfdsTun      { -1 };    
            std::vector<char>       buff;
            debugmode::DEBUG_MODE   debugMode  { debugmode::ERR_DEBUG };
    
        public:
            NnVpnClient(std::string pem,   std::string key, 
                       std::string paddr, std::string pport, 
                       std::string dev,   size_t buffSize=1500)            anyexcept;
            ~NnVpnClient(void)                                             noexcept;
    
            void                   init(std::string tunIpString, 
                                        std::string tunMaskString)         anyexcept;
            void                   start(void)                             anyexcept;
    };

    class NnVpnServer : public Tun{
        private:
            InetServerSSL           sslServer;
            std::string             srvAddr      { "" },
                                    srvPort      { "" };
            size_t                  bufferSize;
            int                     nfdsTun      { -1 };    
            std::vector<char>       buff;
            debugmode::DEBUG_MODE   debugMode  { debugmode::ERR_DEBUG };
    
        public:
            NnVpnServer(std::string pem,   std::string key, 
                       std::string saddr, std::string sport, 
                       std::string dev,   size_t buffSize=1500)            anyexcept;
            ~NnVpnServer(void)                                             noexcept;

            void                   init(std::string tunIpString, 
                                        std::string tunMaskString)         anyexcept;
            void                   start(void)                             anyexcept;
    };

} //End Namespace

