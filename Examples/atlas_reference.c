/* Original reference implementations for Atlas signatures, MIT licensed.
 * These are deliberately simple C library routines, not vendor libc source.
 * Signatures describe these builds, not every implementation of these APIs. */
typedef __SIZE_TYPE__ size_t;
void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest; const unsigned char *s = src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}
void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = dest; const unsigned char *s = src;
    if (d < s) { for (size_t i = 0; i < n; ++i) d[i] = s[i]; }
    else if (d > s) { while (n) { --n; d[n] = s[n]; } }
    return dest;
}
void *memset(void *dest, int c, size_t n) {
    unsigned char *d = dest;
    for (size_t i = 0; i < n; ++i) d[i] = (unsigned char)c;
    return dest;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < n; ++i) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}
size_t strlen(const char *s) {
    size_t n = 0; while (s[n]) ++n; return n;
}
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}
int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}
char *strchr(const char *s, int c) {
    for (;;) { if ((unsigned char)*s == (unsigned char)c) return (char *)s; if (!*s) return (void *)0; ++s; }
}
