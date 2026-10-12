/*
 * A1-22 minimal Gramine-SGX probe.
 *
 * Runs inside a Gramine enclave with sgx.debug disabled and asks the
 * attestation pseudo-filesystem for a DCAP quote bound to a fixed
 * report-data block. The quote is printed as hex so the host can capture it
 * without the enclave needing a writable mount.
 */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define A122_REPORT_DATA_LEN 64
#define A122_MAX_QUOTE_LEN 16384

int main(void) {
    unsigned char report_data[A122_REPORT_DATA_LEN];
    for (size_t i = 0; i < sizeof(report_data); i++) {
        report_data[i] = (unsigned char)(0xA1u ^ (unsigned char)i);
    }

    int fd = open("/dev/attestation/user_report_data", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open user_report_data: %s\n", strerror(errno));
        return 2;
    }
    if (write(fd, report_data, sizeof(report_data)) !=
        (ssize_t)sizeof(report_data)) {
        fprintf(stderr, "write user_report_data: %s\n", strerror(errno));
        close(fd);
        return 3;
    }
    close(fd);

    static unsigned char quote[A122_MAX_QUOTE_LEN];
    fd = open("/dev/attestation/quote", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open quote: %s\n", strerror(errno));
        return 4;
    }
    ssize_t n = read(fd, quote, sizeof(quote));
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "read quote: %s\n", strerror(errno));
        return 5;
    }

    printf("A1_22_GRAMINE_HELLO_BEGIN\n");
    printf("report_data_hex=");
    for (size_t i = 0; i < sizeof(report_data); i++) {
        printf("%02x", report_data[i]);
    }
    printf("\n");
    printf("quote_len=%zd\n", n);
    printf("quote_hex=");
    for (ssize_t i = 0; i < n; i++) {
        printf("%02x", quote[i]);
    }
    printf("\n");
    printf("A1_22_GRAMINE_HELLO_END\n");
    return 0;
}
