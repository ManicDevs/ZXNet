#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void util_sleep(int tosleep);

void util_msgc(const char *type, const char *fmt, ...);

void util_strxor(char out[], void *_buf, int len);

void util_trim(char *str);

char *util_type2str(int type);

#endif /* utils_h */
