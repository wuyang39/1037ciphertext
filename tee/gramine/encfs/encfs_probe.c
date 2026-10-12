/*
 * A1-22 Gramine encrypted-FS probe.
 *
 * A 16-byte key is read from stdin and installed as the named Gramine
 * encrypted-files key through /dev/attestation/keys/<name>. The probe then
 * reads one file from the encrypted mount end to end, so a truncated read, a
 * bad key or a tampered block all surface as a failure. Only the first few
 * kilobytes are printed; the byte count covers the whole file.
 *
 * Usage: encfs_probe <key_name> <guest_file>
 */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define A122_KEY_BYTES 16
#define A122_PREFIX_BYTES 4096
#define A122_CHUNK_BYTES 65536

static int install_key(const char *key_name) {
    unsigned char key[A122_KEY_BYTES];
    size_t got = 0;
    while (got < sizeof(key)) {
        ssize_t n = read(STDIN_FILENO, key + got, sizeof(key) - got);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }

    char path[256];
    if (snprintf(path, sizeof(path), "/dev/attestation/keys/%s", key_name) >=
        (int)sizeof(path)) {
        return -2;
    }
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -3;
    }
    if (write(fd, key, sizeof(key)) != (ssize_t)sizeof(key)) {
        fprintf(stderr, "write %s: %s\n", path, strerror(errno));
        close(fd);
        return -4;
    }
    close(fd);
    memset(key, 0, sizeof(key));
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <key_name> <guest_file>\n", argv[0]);
        return 2;
    }
    const char *key_name = argv[1];
    const char *guest_file = argv[2];

    printf("A1_22_ENCFS_BEGIN\n");
    printf("key_name=%s\n", key_name);
    printf("guest_file=%s\n", guest_file);

    int key_status = install_key(key_name);
    printf("key_installed=%d\n", key_status == 0 ? 1 : 0);
    printf("key_status=%d\n", key_status);

    static unsigned char prefix[A122_PREFIX_BYTES];
    static unsigned char chunk[A122_CHUNK_BYTES];
    size_t prefix_len = 0;
    long long total = 0;
    int read_errno = 0;

    int fd = open(guest_file, O_RDONLY);
    if (fd < 0) {
        printf("read_ok=0\n");
        printf("read_errno=%d\n", errno);
        printf("read_error=%s\n", strerror(errno));
        printf("A1_22_ENCFS_END\n");
        return 3;
    }
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            read_errno = errno;
            total = -1;
            break;
        }
        if (n == 0) {
            break;
        }
        if (prefix_len < sizeof(prefix)) {
            size_t room = sizeof(prefix) - prefix_len;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(prefix + prefix_len, chunk, take);
            prefix_len += take;
        }
        total += (long long)n;
    }
    close(fd);
    if (total < 0) {
        printf("read_ok=0\n");
        printf("read_errno=%d\n", read_errno);
        printf("read_error=%s\n", strerror(read_errno));
        printf("A1_22_ENCFS_END\n");
        return 4;
    }

    printf("read_ok=1\n");
    printf("content_len=%lld\n", total);
    printf("content_prefix_len=%zu\n", prefix_len);
    printf("content_hex=");
    for (size_t i = 0; i < prefix_len; i++) {
        printf("%02x", prefix[i]);
    }
    printf("\n");
    printf("A1_22_ENCFS_END\n");
    return 0;
}
