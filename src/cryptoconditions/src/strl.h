
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

#ifndef HAVE_DECL_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t dsize);
#endif

#ifndef HAVE_DECL_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t dsize);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* STRL_H */
