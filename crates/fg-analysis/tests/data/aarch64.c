__attribute__((noreturn)) void abort(void);
int dep_value(int);

volatile int input;

typedef int (*op_fn)(int, int);
__attribute__((noinline)) static int op_add(int a, int b) { return a + b; }
__attribute__((noinline)) static int op_sub(int a, int b) { return a - b; }
__attribute__((noinline)) static int op_mul(int a, int b) { return a * b; }
__attribute__((noinline)) static int op_xor(int a, int b) { return a ^ b; }
static op_fn volatile table[] = { op_add, op_sub, op_mul, op_xor };

__attribute__((noinline)) static int only_from_a_case(int v) { return v * 5 + dep_value(v); }
__attribute__((noinline, noreturn)) static void die(void) { abort(); }

__attribute__((noinline)) static int classify(int c, int v) {
    switch (c) {
    case 0: return dep_value(v);
    case 1: return only_from_a_case(v) + 1;
    case 2: return table[v & 3](v, c) + 1;
    case 3: return dep_value(v) * 7;
    case 4: return v * v + 3;
    case 5: return dep_value(v + 9) - 2;
    case 6: die();
    case 7: return (v << 3) ^ dep_value(1);
    case 8: return dep_value(v) + v;
    case 9: return v / 3 + dep_value(2);
    case 10: return only_from_a_case(v + 4) * 3;
    case 11: return dep_value(v ^ 0x55);
    case 12: return table[3](v, 7) + 1;
    case 13: return dep_value(v) - dep_value(v + 1);
    default: return -1;
    }
}

void _start(void) {
    input = classify(input, input + 1);
    die();
}
