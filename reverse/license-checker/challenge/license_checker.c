/*
 * License Checker - CTF Challenge
 * Reverse engineer this program to find the valid license key
 *
 * Compile: gcc -o license_checker license_checker.c
 * Run: ./license_checker <license_key>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// The flag that gets revealed with correct license
#define FLAG "CTF{r3v3rs3_3ng1n33r1ng_m4st3r}"

// Hidden validation data
static const char VALIDATION_DATA[] = "SECRETKEY2024";
static const int CHECKSUM = 0x29F0;

// Simple XOR encoding for obfuscation
void xor_encode(char *data, int len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Validate the license key format: XXXX-XXXX-XXXX-XXXX
int check_format(const char *license) {
    if (strlen(license) != 19) return 0;

    // Check dash positions
    if (license[4] != '-' || license[9] != '-' || license[14] != '-') {
        return 0;
    }

    // Check alphanumeric characters
    for (int i = 0; i < 19; i++) {
        if (i == 4 || i == 9 || i == 14) continue;
        char c = license[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
            return 0;
        }
    }

    return 1;
}

// Calculate a simple checksum
int calculate_checksum(const char *license) {
    int sum = 0;
    for (int i = 0; license[i] != '\0'; i++) {
        sum += (unsigned char)license[i] * (i + 1);
    }
    return sum;
}

// Validate each segment of the license
int validate_segment(const char *segment, int segment_num) {
    // Each segment must satisfy certain conditions
    int sum = 0;
    int product = 1;

    for (int i = 0; i < 4; i++) {
        char c = segment[i];
        int val;

        if (c >= 'A' && c <= 'Z') {
            val = c - 'A' + 10;
        } else {
            val = c - '0';
        }

        sum += val;
        product *= (val % 10) + 1;
    }

    // Segment-specific validation
    switch (segment_num) {
        case 1:
            // First segment sum must equal 42
            return sum == 42;
        case 2:
            // Second segment: first char 'C', last char '4'
            return segment[0] == 'C' && segment[3] == '4';
        case 3:
            // Third segment: all numeric
            for (int i = 0; i < 4; i++) {
                if (segment[i] < '0' || segment[i] > '9') return 0;
            }
            return 1;
        case 4:
            // Fourth segment: product must equal 36
            return product == 36;
        default:
            return 0;
    }
}

// Main validation function
int validate_license(const char *license) {
    // Step 1: Check format
    if (!check_format(license)) {
        printf("[-] Invalid format! Expected: XXXX-XXXX-XXXX-XXXX\n");
        return 0;
    }

    printf("[+] Format check passed\n");

    // Step 2: Extract segments
    char segments[4][5];
    for (int i = 0; i < 4; i++) {
        strncpy(segments[i], license + (i * 5), 4);
        segments[i][4] = '\0';
    }

    // Step 3: Validate each segment
    for (int i = 0; i < 4; i++) {
        if (!validate_segment(segments[i], i + 1)) {
            printf("[-] Segment %d validation failed!\n", i + 1);
            return 0;
        }
        printf("[+] Segment %d validated: %s\n", i + 1, segments[i]);
    }

    // Step 4: Check overall checksum
    int checksum = calculate_checksum(license);
    if (checksum != CHECKSUM) {
        printf("[-] Invalid checksum! Got %d, expected %d\n", checksum, CHECKSUM);
        return 0;
    }
    printf("[+] Checksum verified\n");

    return 1;
}

// Print usage information
void print_usage(const char *program) {
    printf("License Checker v1.0\n");
    printf("Usage: %s <license_key>\n\n", program);
    printf("License format: XXXX-XXXX-XXXX-XXXX\n");
    printf("Where X is alphanumeric (A-Z, 0-9)\n");
}

// Anti-debugging check (simple)
int check_debugger() {
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                if (pid != 0) {
                    fclose(f);
                    return 1;  // Debugger detected
                }
            }
        }
        fclose(f);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    // Check for debugger
    if (check_debugger()) {
        printf("[-] Debugger detected! Exiting...\n");
        return 1;
    }

    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *license = argv[1];

    printf("[*] Validating license: %s\n\n", license);

    if (validate_license(license)) {
        printf("\n[+] License validated successfully!\n");
        printf("[+] FLAG: %s\n", FLAG);
        return 0;
    } else {
        printf("\n[-] License validation failed!\n");
        return 1;
    }
}
