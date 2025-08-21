
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    const char *input1 = "aGVsbG8gd29ybGQh";     // no padding
    const char *input2 = "aGVsbG8gd29ybGQh=";    // 1 padding
    const char *input3 = "aGVsbG8gd29ybGQh==";   // 2 padding
    
    unsigned char output[100];
    int result;
    
    printf("Testing EVP_DecodeBlock:\n");
    
    printf("\nNo padding: '%s'\n", input1);
    result = EVP_DecodeBlock(output, (const unsigned char*)input1, strlen(input1));
    printf("Result: %d\n", result);
    if (result >= 0) {
        output[result] = '\0';
        printf("Output: '%s'\n", output);
    }
    
    printf("\n1 padding: '%s'\n", input2);
    result = EVP_DecodeBlock(output, (const unsigned char*)input2, strlen(input2));
    printf("Result: %d\n", result);
    if (result >= 0) {
        output[result] = '\0';
        printf("Output: '%s'\n", output);
    }
    
    printf("\n2 padding: '%s'\n", input3);
    result = EVP_DecodeBlock(output, (const unsigned char*)input3, strlen(input3));
    printf("Result: %d\n", result);
    if (result >= 0) {
        output[result] = '\0';
        printf("Output: '%s'\n", output);
    }
    
    return 0;
}

