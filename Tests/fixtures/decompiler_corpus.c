typedef unsigned int u32;
typedef int i32;
typedef unsigned long long u64;
__attribute__((noinline)) u32 dc_mix(u32 a, u32 b) { return ((a * 7u) ^ (b + 19u)) + 3u; }
__attribute__((noinline)) u32 dc_choose(i32 a, i32 b) { if (a < b) return (u32)a + 7u; return (u32)b - 3u; }
__attribute__((noinline)) u32 dc_range(i32 x, u32 y) { if (x >= 10 && x <= 40) return y + 99u; return y ^ 0x1234u; }
__attribute__((noinline)) u32 dc_unsigned(u32 a, u32 b) { return a > b ? a - b : b + a; }
__attribute__((noinline)) u32 dc_loop(u32 n, u32 seed) { u32 acc = seed; for (u32 i=0; i<(n & 15u); i++) acc = (acc ^ i) + 3u; return acc; }
__attribute__((noinline)) u32 dc_while(u32 n, u32 x) { while (n != 0) { x = (x + n) ^ 7u; --n; if (n == 17) break; } return x; }
__attribute__((noinline)) u32 dc_byte(u32 x, u32 y) { return (u32)(signed char)x + (u32)(unsigned char)y; }
__attribute__((noinline)) u64 dc_wide(u64 x, u64 y) { return (x >> 11) ^ (y * 13ull); }
__attribute__((noinline)) u32 dc_select(u32 x, u32 y) { return x == 7 ? y + 1u : y - 1u; }
