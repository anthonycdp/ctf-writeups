/*
 * Stack Overflow 101 - CTF Challenge
 * Analyze this binary to understand the vulnerability and find the flag
 *
 * Compile with:
 * gcc -fno-stack-protector -z execstack -no-pie -o stack_overflow stack_overflow.c
 *
 * The flag is hidden in the binary - you need to find it!
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Hidden flag (will be embedded in the binary)
const char FLAG[] = "CTF{buff3r_0v3rfl0w_101_c0mpl3t3}";

// Secret function that prints the flag (never called directly)
void secret_function() {
    printf("\n");
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║         🎉 CONGRATULATIONS! 🎉                 ║\n");
    printf("║    You've successfully exploited the buffer!   ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║  Flag: %s   ║\n", FLAG);
    printf("╚════════════════════════════════════════════════╝\n");
    printf("\n");
}

// Vulnerable function
void vulnerable_function(char *input) {
    char buffer[64];  // Fixed-size buffer - VULNERABILITY!

    printf("[*] Copying input to buffer...\n");
    strcpy(buffer, input);  // No bounds checking!

    printf("[*] Buffer contents: %s\n", buffer);
    printf("[*] Return address will be at: %p\n", __builtin_return_address(0));
}

void win() {
    // Alternative win function for those who find it
    system("cat /flag.txt");
}

int main(int argc, char *argv[]) {
    // Disable buffering for clearer output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("╔════════════════════════════════════════════════╗\n");
    printf("║      Stack Overflow Challenge - Level 1        ║\n");
    printf("║                                                ║\n");
    printf("║  Can you redirect execution to secret_function?║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        printf("\nHint: The buffer is 64 bytes. What happens with more?\n");
        printf("Hint: Find the address of secret_function!\n");
        return 1;
    }

    printf("[*] Address of secret_function: %p\n", (void*)secret_function);
    printf("[*] Address of win: %p\n", (void*)win);
    printf("[*] Input length: %zu bytes\n\n", strlen(argv[1]));

    // Call the vulnerable function with user input
    vulnerable_function(argv[1]);

    printf("\n[*] Function returned normally. Try again!\n");

    return 0;
}
