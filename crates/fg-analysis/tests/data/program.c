#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*op_fn)(int, int);

/* Reached only through a table of pointers. */
static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }
static int op_mul(int a, int b) { return a * b; }
static int op_xor(int a, int b) { return a ^ b; }
static op_fn table[] = { op_add, op_sub, op_mul, op_xor };

/* A cold path the compiler splits off. */
__attribute__((noinline)) static int checked(int v) {
    if (__builtin_expect(v < 0, 0)) {
        fprintf(stderr, "negative %d\n", v);
        abort();
    }
    return v * 3;
}

/* Frameless, with a cold path gcc splits off under an FDE of its own that
   starts in the same unwind state as a function. */
__attribute__((noinline)) int get_reg(const int *regs, unsigned i) {
    if (i >= 16) abort();
    return regs[i];
}

/* Reached by a tail call only. */
__attribute__((noinline)) static int tail_target(int v) { return checked(v) + 7; }
__attribute__((noinline)) int via_tail(int v) { return tail_target(v + 1); }

/* A thunk: nothing but a jump. */
__attribute__((noinline)) int thunk(int v) { return via_tail(v); }

/* Never return: through exit, through another such function, and by looping
   forever. */
__attribute__((noinline, noreturn)) static void die(const char *m) { fputs(m, stderr); exit(2); }
__attribute__((noinline, noreturn)) static void give_up(int v) { fprintf(stderr, "%d: ", v); die("giving up\n"); }
__attribute__((noinline, noreturn)) static void spin(void) { for (;;) pause(); }

__attribute__((noinline)) static void reverse(char *s) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) { char t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t; }
}

/* Called only from a case of the switch below. */
__attribute__((noinline)) static int only_from_a_case(const char *s) { return (int)strlen(s) * 5; }

/* A switch dense enough for a jump table, with different code in every case
   so that it does not become a table of values. */
__attribute__((noinline)) static int classify(int c, char *s) {
    switch (c) {
    case 0: return puts(s);
    case 1: reverse(s); return 1;
    case 2: return atoi(s);
    case 3: return only_from_a_case(s) + 1;
    case 4: return (int)getpid();
    case 5: return putchar(*s);
    case 6: return fputs(s, stderr);
    case 7: return (int)write(1, s, 1);
    default: return -1;
    }
}

int main(int argc, char **argv) {
    int acc = 0, regs[16] = {0};
    acc += get_reg(regs, (unsigned)argc);
    if (argc > 9) give_up(argc);
    if (argc > 8) spin();
    if (argc == 0) die("no arguments\n");
    for (int i = 1; i < argc; i++) {
        acc = table[i % 4](acc, atoi(argv[i]));
        reverse(argv[i]);
        puts(argv[i]);
    }
    acc += classify(argc, argv[0]);
    printf("%d\n", thunk(acc));
    return 0;
}
