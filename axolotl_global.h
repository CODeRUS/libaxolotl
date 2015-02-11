#ifndef AXOLOTL_GLOBAL_H
#define AXOLOTL_GLOBAL_H

// from https://gcc.gnu.org/wiki/Visibility
#if defined _WIN32 || defined __CYGWIN__
  #ifdef LIBAXOLOTL_LIBRARY
    #ifdef __GNUC__
      #define LIBAXOLOTL_DLL __attribute__ ((dllexport))
    #else
      #define LIBAXOLOTL_DLL __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define LIBAXOLOTL_DLL __attribute__ ((dllimport))
    #else
      #define LIBAXOLOTL_DLL __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define LIBAXOLOTL_DLL __attribute__ ((visibility ("default")))
  #else
    #define LIBAXOLOTL_DLL
  #endif
#endif

#endif // AXOLOTL_GLOBAL_H
