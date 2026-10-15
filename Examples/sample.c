#include <stdio.h>
#include <string.h>
#include <unistd.h>

volatile int atlas_counter = 7;
__attribute__((noinline)) int score_input(const char *text) {
    int score = 0;
    for (size_t i = 0; i < strlen(text); ++i) {
        if (text[i] >= 'a' && text[i] <= 'z') score += 3;
        else if (text[i] >= '0' && text[i] <= '9') score += 2;
        else score -= 1;
    }
    return score + atlas_counter;
}
int main(int argc, char **argv) {
    const char *input = argc > 1 ? argv[1] : "hello-asteria";
    puts("Asteria training binary — static and dynamic analysis");
    int result = score_input(input);
    printf("input=%s score=%d\n", input, result);
    if (argc > 2 && strcmp(argv[2], "--wait") == 0) {
        puts("Waiting for debugger; inspect atlas_counter or pause execution.");
        for (int i = 0; i < 30; i++) { atlas_counter++; sleep(1); }
    }
    return result < 0 ? 1 : 0;
}
