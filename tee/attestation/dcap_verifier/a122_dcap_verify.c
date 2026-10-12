/* A1-22 DCAP quote verifier.
 *
 * This is the ``KAS_DCAP_VERIFY_BIN`` adapter consumed by kas/dcap.py. It
 * verifies an SGX ECDSA quote with the Intel DCAP quote verification library
 * and prints the measured claims as JSON:
 *
 *   a122_dcap_verify --quote <path> --json
 *
 * It exits 0 when the quote is cryptographically valid and the TCB result is
 * non-terminal, and non-zero for terminal failures (invalid signature,
 * revoked, unspecified) so that the KAS fails closed.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sgx_dcap_quoteverify.h"
#include "sgx_quote.h"

#define QUOTE_HEADER_BYTES 48u
#define REPORT_BODY_BYTES 384u
#define SIGNATURE_DATA_LEN_BYTES 4u
#define MIN_QUOTE_BYTES \
    (QUOTE_HEADER_BYTES + REPORT_BODY_BYTES + SIGNATURE_DATA_LEN_BYTES)

#define REPORT_ATTRIBUTES_OFFSET 48u
#define REPORT_MRENCLAVE_OFFSET 64u
#define REPORT_MRSIGNER_OFFSET 128u
#define REPORT_ISV_PROD_ID_OFFSET 256u
#define REPORT_ISV_SVN_OFFSET 258u
#define REPORT_REPORT_DATA_OFFSET 320u

#define SGX_ATTRIBUTES_DEBUG 0x2ULL

/* Quote verification results are ``0x0000`` (OK) or ``0xA000 | code``. */
#define TEE_QV_RESULT_PREFIX 0xA000u

static uint64_t load_u64le(const uint8_t *p) {
    uint64_t value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | p[i];
    }
    return value;
}

static uint16_t load_u16le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t load_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int base64_encode(const uint8_t *in, size_t len, char *out, size_t out_len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const size_t needed = ((len + 2u) / 3u) * 4u + 1u;
    if (out_len < needed) {
        return -1;
    }
    size_t i = 0;
    size_t o = 0;
    while (i + 3u <= len) {
        const uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                           (uint32_t)in[i + 2];
        out[o++] = table[(v >> 18) & 0x3F];
        out[o++] = table[(v >> 12) & 0x3F];
        out[o++] = table[(v >> 6) & 0x3F];
        out[o++] = table[v & 0x3F];
        i += 3u;
    }
    if (i < len) {
        uint32_t v = (uint32_t)in[i] << 16;
        const int rem = (int)(len - i);
        if (rem == 2) {
            v |= (uint32_t)in[i + 1] << 8;
        }
        out[o++] = table[(v >> 18) & 0x3F];
        out[o++] = table[(v >> 12) & 0x3F];
        out[o++] = rem == 2 ? table[(v >> 6) & 0x3F] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", bytes[i]);
    }
}

static uint8_t *read_file(const char *path, size_t *size_out) {
    FILE *handle = fopen(path, "rb");
    if (handle == NULL) {
        return NULL;
    }
    if (fseek(handle, 0, SEEK_END) != 0) {
        fclose(handle);
        return NULL;
    }
    const long length = ftell(handle);
    if (length <= 0) {
        fclose(handle);
        return NULL;
    }
    rewind(handle);
    uint8_t *buffer = (uint8_t *)malloc((size_t)length);
    if (buffer == NULL) {
        fclose(handle);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)length, handle) != (size_t)length) {
        free(buffer);
        fclose(handle);
        return NULL;
    }
    fclose(handle);
    *size_out = (size_t)length;
    return buffer;
}

int main(int argc, char *argv[]) {
    const char *quote_path = NULL;
    int json_mode = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--quote") == 0 && i + 1 < argc) {
            quote_path = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            json_mode = 1;
        } else {
            fprintf(stderr, "usage: %s --quote <path> [--json]\n", argv[0]);
            return 2;
        }
    }
    if (quote_path == NULL) {
        fprintf(stderr, "usage: %s --quote <path> [--json]\n", argv[0]);
        return 2;
    }

    size_t quote_size = 0;
    uint8_t *quote = read_file(quote_path, &quote_size);
    if (quote == NULL) {
        fprintf(stderr, "error: cannot read quote from %s\n", quote_path);
        return 1;
    }
    if (quote_size < MIN_QUOTE_BYTES) {
        fprintf(stderr, "error: quote is shorter than the fixed ECDSA layout\n");
        free(quote);
        return 1;
    }

    /* Parse the measured claims from the report body, which is covered by the
     * quote signature that the DCAP library verifies below. */
    const uint8_t *body = quote + QUOTE_HEADER_BYTES;
    const uint64_t attribute_flags =
        load_u64le(body + REPORT_ATTRIBUTES_OFFSET);
    const uint16_t isv_prod_id = load_u16le(body + REPORT_ISV_PROD_ID_OFFSET);
    const uint16_t isv_svn = load_u16le(body + REPORT_ISV_SVN_OFFSET);
    const uint8_t *report_data = body + REPORT_REPORT_DATA_OFFSET;
    const uint32_t signature_data_len =
        load_u32le(quote + QUOTE_HEADER_BYTES + REPORT_BODY_BYTES);
    const int is_debug = (attribute_flags & SGX_ATTRIBUTES_DEBUG) ? 1 : 0;

    tee_supp_data_descriptor_t supplemental;
    memset(&supplemental, 0, sizeof(supplemental));
    uint32_t supplemental_size = 0;
    uint32_t supplemental_version = 0;
    const quote3_error_t size_ret = tee_get_supplemental_data_version_and_size(
        quote, (uint32_t)quote_size, &supplemental_version, &supplemental_size);
    if (size_ret == SGX_QL_SUCCESS && supplemental_size > 0) {
        supplemental.p_data = (uint8_t *)calloc(1, supplemental_size);
        supplemental.data_size = supplemental.p_data != NULL ? supplemental_size : 0;
    }

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    const quote3_error_t verify_ret = tee_verify_quote(
        quote, (uint32_t)quote_size, NULL, time(NULL),
        &collateral_expiration_status, &verification_result, NULL,
        &supplemental);

    const uint32_t result_code =
        ((uint32_t)verification_result) & 0xFFu;
    int accepted = 0;
    if (verify_ret == SGX_QL_SUCCESS) {
        switch (result_code) {
            case 0x00u: /* OK                            */
            case 0x01u: /* CONFIG_NEEDED                 */
            case 0x02u: /* OUT_OF_DATE                   */
            case 0x03u: /* OUT_OF_DATE_CONFIG_NEEDED     */
            case 0x07u: /* SW_HARDENING_NEEDED           */
            case 0x08u: /* CONFIG_AND_SW_HARDENING_NEEDED*/
                accepted = 1;
                break;
            default:
                accepted = 0;
                break;
        }
    }

    if (!json_mode) {
        printf("verify_ret=0x%04x verification_result=0x%08x accepted=%d\n",
               (unsigned)verify_ret, (unsigned)verification_result, accepted);
        if (!accepted) {
            free(supplemental.p_data);
            free(quote);
            return 1;
        }
        free(supplemental.p_data);
        free(quote);
        return 0;
    }

    char report_data_b64[128];
    if (base64_encode(report_data, 64, report_data_b64, sizeof(report_data_b64)) != 0) {
        fprintf(stderr, "error: failed to encode REPORTDATA\n");
        free(supplemental.p_data);
        free(quote);
        return 1;
    }

    if (!accepted) {
        fprintf(stderr,
                "DCAP verification rejected the quote: verify=0x%04x result=0x%08x\n",
                (unsigned)verify_ret, (unsigned)verification_result);
        free(supplemental.p_data);
        free(quote);
        return 1;
    }

    printf("{\n");
    printf("  \"mrenclave\": \"");
    print_hex(body + REPORT_MRENCLAVE_OFFSET, 32);
    printf("\",\n");
    printf("  \"mrsigner\": \"");
    print_hex(body + REPORT_MRSIGNER_OFFSET, 32);
    printf("\",\n");
    printf("  \"isvsvn\": %u,\n", (unsigned)isv_svn);
    printf("  \"isv_prod_id\": %u,\n", (unsigned)isv_prod_id);
    printf("  \"debug\": %s,\n", is_debug ? "true" : "false");
    printf("  \"report_data_b64\": \"%s\",\n", report_data_b64);
    printf("  \"attributes_flags\": \"0x%016llx\",\n",
           (unsigned long long)attribute_flags);
    printf("  \"quote_size\": %u,\n", (unsigned)quote_size);
    printf("  \"signature_data_len\": %u,\n", (unsigned)signature_data_len);
    printf("  \"dcap_verify_status\": \"0x%04x\",\n", (unsigned)verify_ret);
    printf("  \"dcap_verification_result\": \"0x%08x\",\n",
           (unsigned)verification_result);
    printf("  \"dcap_result_prefix\": \"0x%04x\",\n", TEE_QV_RESULT_PREFIX);
    printf("  \"collateral_expiration_status\": %u,\n",
           (unsigned)collateral_expiration_status);
    printf("  \"supplemental_data_version\": %u\n",
           (unsigned)supplemental_version);
    printf("}\n");

    free(supplemental.p_data);
    free(quote);
    return 0;
}
