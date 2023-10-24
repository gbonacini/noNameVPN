// -----------------------------------------------------------------
// Typeutils - safe conversion library
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

#include <sys/types.h>
#include <cstddef>
#include <cstdint> 

#include <exception>
#include <limits>
#include <string>

#include <anyexcept.hpp>
#include <ConceptsLib.hpp>

namespace typeutils{

   class  TypesUtilsException final : public std::exception {
           public:
                   explicit    TypesUtilsException(int errNum);
                   explicit    TypesUtilsException(const char* errString);
                   explicit    TypesUtilsException(std::string& errString);
                               TypesUtilsException(int errNum, const char* errString);
                               TypesUtilsException(int errNum, std::string& errString);
                   const char* what(void)                                                     const noexcept override;
                   int         getErrorCode(void)                                             const noexcept;
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wsign-compare"
   #endif

   #ifdef __GNUC__
   #pragma GCC diagnostic push
   #pragma GCC diagnostic ignored "-Wsign-compare"
   #pragma GCC diagnostic ignored "-Wtype-limits"
   #endif

   template<typename T>
   T safeSizeRange(long long number, long long min=1) anyexcept {
      if(min < 0)
           throw TypesUtilsException("Invalid Range: min can't be negative.");

      if(number < min || number > std::numeric_limits<T>::max()) 
           throw TypesUtilsException("Invalid Range.");
      return static_cast<T>(number);
   }

   ssize_t safeSsizeT(conceptsLib::Integral auto size)  anyexcept {     
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion: negative value not allowed.");
      if(size > std::numeric_limits<ssize_t>::max())
         throw TypesUtilsException("Invalid conversion to ssize_t: overflow.");
      return static_cast<ssize_t>(size);
   }

   int safeInt(conceptsLib::Integral auto size)  anyexcept {        
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion: negative value not allowed.");
      if(size > std::numeric_limits<int>::max())
         throw TypesUtilsException("Invalid conversion to int: overflow.");
      return static_cast<int>(size);
   }

   ptrdiff_t safePtrdiff(conceptsLib::Integral auto offset)  anyexcept {  
      if(offset < 0)       
         throw TypesUtilsException("Invalid conversion: negative value not allowed.");
      if(offset > std::numeric_limits<ptrdiff_t>::max())
         throw TypesUtilsException("Invalid conversion to ptrdiff_t: overflow.");
      return static_cast<ptrdiff_t>(offset);
   }

   ssize_t safeSsizeTSigned(conceptsLib::Integral auto size)  anyexcept {     
      if(size > std::numeric_limits<ssize_t>::max() || size < std::numeric_limits<ssize_t>::min() )
         throw TypesUtilsException("Invalid conversion to ssize_t: range.");
      return static_cast<ssize_t>(size);
   }

   int safeIntSigned(conceptsLib::Integral auto size)  anyexcept {        
      if(size > std::numeric_limits<int>::max() || size < std::numeric_limits<int>::min()   )
         throw TypesUtilsException("Invalid conversion to int: range.");
      return static_cast<int>(size);
   }

   ptrdiff_t safePtrdiffSigned(conceptsLib::Integral auto offset)  anyexcept {  
      if(offset > std::numeric_limits<ptrdiff_t>::max() || offset < std::numeric_limits<ptrdiff_t>::min() )
         throw TypesUtilsException("Invalid conversion to ptrdiff_t: range.");
      return static_cast<ptrdiff_t>(offset);
   }

   size_t safeSizeT(conceptsLib::Integral auto size)  anyexcept {
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to size_t: negative value.");
      if(size > std::numeric_limits<size_t>::max())
         throw TypesUtilsException("Invalid conversion to size_t: overflow.");
      return static_cast<size_t>(size);
   }

   uint8_t safeUint8(conceptsLib::Integral auto size)  anyexcept {
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to uint8_t: negative value.");
      if(size > std::numeric_limits<uint8_t>::max())
         throw TypesUtilsException("Invalid conversion to uint8_t: overflow.");
      return static_cast<uint8_t>(size);
   }

   unsigned int safeUInt(conceptsLib::Integral auto size)  anyexcept {       
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned int: negative value.");
      if(size > std::numeric_limits<unsigned int>::max())
         throw TypesUtilsException("Invalid conversion to unsigned int: overflow.");
      return static_cast<unsigned int>(size);
   }

   unsigned long safeULong(conceptsLib::Integral auto size)  anyexcept {      
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned long: negative value.");
      if(size > std::numeric_limits<unsigned long>::max())
         throw TypesUtilsException("Invalid conversion to unsigned long: overflow.");
      return static_cast<unsigned long>(size);
   }

   uint32_t safeUint32(conceptsLib::Integral auto size)  anyexcept {     
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to uint32_t: negative value.");
      if(size > std::numeric_limits<uint32_t>::max())
         throw TypesUtilsException("Invalid conversion to uint32_t: overflow.");
      return static_cast<uint32_t>(size);
   }

   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif

   extern template uint16_t        safeSizeRange<uint16_t>(long long, long long)       anyexcept;
   extern template int             safeSizeRange<int>(long long, long long)            anyexcept;
   extern template size_t          safeSizeRange<size_t>(long long, long long)         anyexcept;
   extern template ssize_t         safeSizeRange<ssize_t>(long long, long long)        anyexcept;
   extern template ptrdiff_t       safePtrdiff<size_t>(size_t)                         anyexcept;
   extern template ssize_t         safeSsizeT<size_t>(size_t)                          anyexcept;
   extern template int             safeInt<unsigned int>(unsigned int)                 anyexcept;
   extern template int             safeInt<size_t>(size_t)                             anyexcept;
   extern template int             safeInt<ssize_t>(ssize_t)                           anyexcept;
   extern template size_t          safeSizeT<ssize_t>(ssize_t)                         anyexcept;
   extern template size_t          safeSizeT<int>(int)                                 anyexcept;
   extern template size_t          safeSizeT<uint32_t>(uint32_t)                       anyexcept;
   extern template size_t          safeSizeT<long long int>(long long int)             anyexcept;
   extern template uint32_t        safeUint32<int>(int)                                anyexcept;
   extern template uint32_t        safeUint32<unsigned long>(unsigned long)            anyexcept;
   extern template uint8_t         safeUint8(size_t size)                              anyexcept;
   extern template uint8_t         safeUint8(int size)                                 anyexcept;
   extern template unsigned int    safeUInt<size_t>(size_t)                            anyexcept;
   extern template unsigned long   safeULong<int>(int)                                 anyexcept;
   extern template unsigned long   safeULong<long int>(long int)                       anyexcept;
   
   #ifdef __GNUC__
   #pragma GCC diagnostic pop
   #endif
} // End namespace

