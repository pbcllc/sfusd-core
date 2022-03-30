// strlxxx safe function impl for linux
#ifndef STRL_H
#define STRL_H

#ifdef __APPLE__  && __DARWIN_C_LEVEL >= __DARWIN_C_FULL
#undef HAVE_STRLCPY
#undef HAVE_STRLCAT
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
#endif

#include <sys/types.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif



#ifndef HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t dsize);
#endif


#ifndef HAVE_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t dsize);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* STRL_H */
