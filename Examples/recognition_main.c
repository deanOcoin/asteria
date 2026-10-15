/* Entry point for the stripped Atlas recognition demonstration. */
extern unsigned long strlen(const char *);
int main(int argc, char **argv) { return argc > 1 ? (int)strlen(argv[1]) : 0; }
