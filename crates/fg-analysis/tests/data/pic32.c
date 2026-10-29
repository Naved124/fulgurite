/* 32-bit position-independent code: globals reached from the GOT pointer
   (gcc sets it with __x86.get_pc_thunk.bx, clang with `call next; pop`). */
int counter;
static int table[4] = {1, 2, 3, 4};
static const char *greeting = "hello";

__attribute__((noinline)) int bump(int i) {
    counter += table[i & 3];
    return counter;
}

__attribute__((noinline)) const char *greet(void) { return greeting; }

__attribute__((noinline)) void reset(void) { counter = 0; }
