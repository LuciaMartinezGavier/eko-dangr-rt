/*
 * This is a very simple implementation of a debugger detector using the same protocol
 * as the lib xz had.
 * 
 * Compile with
 * $ gcc -fcf-protection=branch -o mini_debug_detection mini_debug_detection.c
 * And run
 *
 * $ ./mini_debug_detection
 *
 * or
 *
 * $ gdb ./mini_debug_detection
 * (gdb) break *foo
 * (gdb) run
*/

#include <stdio.h>
#include <stdint.h>

void foo() { }

int64_t check_software_breakpoint(uint32_t *code_addr, int64_t a2, int a3) {
    unsigned int v4 = 0;
    if (a2 - (int64_t)code_addr > 3) {
        return *code_addr + (a3 | 0x5E20000) == 0xF223;
    }
    return v4;
}

int main() {
    uint32_t *code_addr = (uint32_t *)(uintptr_t)foo;
    printf("Opcode is 0x%x\n", *code_addr);

    if (check_software_breakpoint(code_addr, (int64_t)code_addr+4, 0xe230)) {
        printf("No debugger detected.\n");
    } else {
        printf("Debugger detected!\n");
    }

    return 0;
}
