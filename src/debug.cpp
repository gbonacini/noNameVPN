// -----------------------------------------------------------------
// Debugmode - log file handler
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

#include <cstring>

#include <debug.hpp>
#include <StringUtils.hpp>


namespace debugmode {

   using std::string,
         std::vector,
         std::hex,
         std::dec,
         std::setw,
         std::setfill,
         std::freopen,
         std::cerr,
         std::cout,
         stringutils::mergeStrings;

   Debug::Debug(DEBUG_MODE level) noexcept {
         Debug::debug_mode = level ;
   }

   void Debug::init(const string& filepath)  const anyexcept {
         if( freopen(filepath.c_str(), "w", stderr) == nullptr)
             throw DebugException(mergeStrings({ "Error: Debug can't redirect stderr: ", strerror(errno)}));
   }

   void Debug::setDebugLevel(DEBUG_MODE level) noexcept {
          Debug::debug_mode = level;
   }

   DEBUG_MODE Debug::getDebugLevel(void) noexcept {
          return Debug::debug_mode;
   }

   void Debug::printLog(const string& msg, DEBUG_MODE minLevel) noexcept {
         if(Debug::debug_mode >= minLevel){
             Debug::logMtx.lock();
             cerr << msg << '\n';
             Debug::logMtx.unlock();
         }
   }

   void Debug::printLog(const char* const msg, DEBUG_MODE minLevel) noexcept {
         if(Debug::debug_mode >= minLevel){
            Debug::logMtx.lock();
            cerr << msg << '\n';
            Debug::logMtx.unlock();
         }
   }

   void Debug::trace(const char* header, const uint8_t* buff, const size_t size, size_t begin, size_t end) noexcept{
                Debug::logMtx.lock();
                cerr << '\n' << header << "\n\n";

                bool last  { false },
                     first { false };

                for (size_t i{ 0 }; i < size; i += 16) {
                   cerr << setfill('0') << setw(5) << dec << i << ":  ";
                   for (size_t j{ i }; j < i + 16; j++) {
                      if(end !=0){
                         if(j == begin ){cerr <<  "\033[7m"; first = true;}
                         if(j == end   ){cerr <<  "\033[0m"; last  = true;}
                      }
                      if(j < size) cerr << setfill('0') << setw(2) << hex << static_cast<int>(buff[j]) << " ";
                      else         cerr << "   ";
                   }

                   if(first) {cerr <<  "\033[0m"; }
                   cerr << " ";

                   for (size_t j{i}; j < i + 16; j++) {
                      if(end !=0){
                         if((last || j == begin)){cerr <<  "\033[7m"; last  = false; }
                                if(j == end ){cerr <<  "\033[0m"; last  = false; }
                      }
                      if(j < size){
                         if((buff[j] > 31) && (buff[j] < 128) && (buff[j] != 127)) cerr << buff[j] ;
                         else                                                      cerr << "." ;
                      }
                   }

                   first = false;
                   cerr << '\n';
                }
                cerr << "\n\n";
                Debug::logMtx.unlock();
   }

   void Debug::trace(const string& header, const vector<uint8_t>* buff, size_t begin, size_t end, size_t max) noexcept{
            Debug::logMtx.lock();
            cerr << '\n' << header << "\n\n";

            size_t len    { max ? max : buff->size() };
            bool   last   { false },
                   first  { false };

            for (size_t i{0}; i < len; i += 16) {
               cerr << setfill('0') << setw(5) << dec << i << ":  ";
               for (size_t j{i}; j < i + 16; j++) {
                  if(end !=0){
                     if(j == begin ){cerr <<  "\033[7m"; first = true;}
                     if(j == end   ){cerr <<  "\033[0m"; last  = true;}
                  }
                  if(j < len) cerr << setfill('0') << setw(2) << hex << static_cast<int>(buff->at(j)) << " ";
                  else        cerr << "   ";
               }

               if(first){cerr <<  "\033[0m"; }
               cerr << " ";

               for (size_t j{i}; j < i + 16; j++) {
                  if(end !=0){
                     if(last && !first   ){cerr << "\033[7m"; last  = false; }
                     if(j == begin       ){cerr << "\033[7m"; first = false; }
                     if(j == end         ){cerr << "\033[0m"; last  = false; }
                  }
                  if(j < len){
                     if((buff->at(j) > 31) && (buff->at(j) < 128) && (buff->at(j) != 127)) cerr << buff->at(j) ;
                     else                                                                  cerr << "." ;
                  }
               }
               first = false;
               cerr << '\n';
            }

            cerr << "\n\n";
            Debug::logMtx.unlock();
   }

   void Debug::traceStdout(const char* header, const uint8_t* buff, const size_t size, size_t begin, size_t end) noexcept{
                Debug::screenMtx.lock();
                cout << '\n' << header << "\n\n";

                bool last  { false },
                     first { false };

                for (size_t i{ 0 }; i < size; i += 16) {
                   cout << setfill('0') << setw(5) << dec << i << ":  ";
                   for (size_t j{ i }; j < i + 16; j++) {
                      if(end !=0){
                         if(j == begin ){cout <<  "\033[7m"; first = true;}
                         if(j == end   ){cout <<  "\033[0m"; last  = true;}
                      }
                      if(j < size) cout << setfill('0') << setw(2) << hex << static_cast<int>(buff[j]) << " ";
                      else         cout << "   ";
                   }

                   if(first) {cout <<  "\033[0m"; }
                   cout << " ";

                   for (size_t j{i}; j < i + 16; j++) {
                      if(end !=0){
                         if((last || j == begin)){cout <<  "\033[7m"; last  = false; }
                                if(j == end ){cout <<  "\033[0m"; last  = false; }
                      }
                      if(j < size){
                         if((buff[j] > 31) && (buff[j] < 128) && (buff[j] != 127)) cout << buff[j] ;
                         else                                                      cout << "." ;
                      }
                   }

                   first = false;
                   cout << '\n';
                }
                cout << "\n\n";
                Debug::screenMtx.unlock();
   }

   void Debug::traceStdout(const string& header, const vector<uint8_t>* buff, size_t begin, size_t end, size_t max) noexcept{
            Debug::screenMtx.lock();
            cout << '\n' << header << "\n\n";

            size_t len    { max ? max : buff->size() };
            bool   last   { false },
                   first  { false };

            for (size_t i{0}; i < len; i += 16) {
               cout << setfill('0') << setw(5) << dec << i << ":  ";
               for (size_t j{i}; j < i + 16; j++) {
                  if(end !=0){
                     if(j == begin ){cout <<  "\033[7m"; first = true;}
                     if(j == end   ){cout <<  "\033[0m"; last  = true;}
                  }
                  if(j < len) cout << setfill('0') << setw(2) << hex << static_cast<int>(buff->at(j)) << " ";
                  else        cout << "   ";
               }

               if(first){cout <<  "\033[0m"; }
               cout << " ";

               for (size_t j{i}; j < i + 16; j++) {
                  if(end !=0){
                     if(last && !first   ){cout << "\033[7m"; last  = false; }
                     if(j == begin       ){cout << "\033[7m"; first = false; }
                     if(j == end         ){cout << "\033[0m"; last  = false; }
                  }
                  if(j < len){
                     if((buff->at(j) > 31) && (buff->at(j) < 128) && (buff->at(j) != 127)) cout << buff->at(j) ;
                     else                                                                  cout << "." ;
                  }
               }
               first = false;
               cout << '\n';
            }

            cout << "\n\n";
            Debug::screenMtx.unlock();
   }

   DebugException::DebugException(string& errString)
        : errorMessage{errString}
   {}

    DebugException::DebugException(string&& errString)
        : errorMessage{errString}
   {}

   const char* DebugException::what(void)   const noexcept {
       return errorMessage.c_str();
   }

} // End namespace debugmode
