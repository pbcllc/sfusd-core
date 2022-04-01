
#ifndef STRL_H
#define STRL_H

#include <sys/types.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "cryptoconditions-config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(HAVE_DECL_STRLCPY) || HAVE_DECL_STRLCPY == 0
size_t
strlcpy(char *dst, const char *src, size_t dsize);
#endif

#if !defined(HAVE_DECL_STRLCAT) || HAVE_DECL_STRLCAT == 0 
size_t
strlcat(char *dst, const char *src, size_t dsize);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* STRL_H */
