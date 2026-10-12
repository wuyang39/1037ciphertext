/* A1-22 SGX quote probe.
 *
 * Generates a real DCAP ECDSA quote for a small enclave and binds a caller
 * supplied 64-byte REPORTDATA value into it. The A1-22 KAS binds the temporary
 * node key, node role, release id and one-time challenge nonce into REPORTDATA,
 * so this probe is what lets the KAS closed loop run against real hardware.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "Enclave_u.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_ql_quote.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "sgx_urts.h"

#define ENCLAVE_PATH "enclave.signed.so"
#define REPORT_DATA_BYTES 64u
#define REPORT_DATA_HEX_LEN (REPORT_DATA_BYTES * 2u)

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2u) {
        return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        char pair[3] = {hex[2u * i], hex[2u * i + 1u], '\0'};
        char *end = NULL;
        const long value = strtol(pair, &end, 16);
        if (end != pair + 2 || value < 0 || value > 0xFF) {
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s [--report-data <128 hex chars>] [--out <quote path>]\n",
            program);
}

int main(int argc, char *argv[]) {
    const char *report_data_hex = NULL;
    const char *out_path = "quote.bin";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--report-data") == 0 && i + 1 < argc) {
            report_data_hex = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    if (report_data_hex != NULL &&
        hex_to_bytes(report_data_hex, report_data.d, REPORT_DATA_BYTES) != 0) {
        fprintf(stderr, "error: --report-data must be %u hex characters\n",
                REPORT_DATA_HEX_LEN);
        return 2;
    }

    sgx_enclave_id_t enclave_id = 0;
    sgx_launch_token_t token;
    memset(&token, 0, sizeof(token));
    int updated = 0;
    sgx_status_t status = sgx_create_enclave(
        ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "error: sgx_create_enclave failed: 0x%04x\n", status);
        return 1;
    }

    sgx_target_info_t qe_target_info;
    memset(&qe_target_info, 0, sizeof(qe_target_info));
    quote3_error_t qe3 = sgx_qe_get_target_info(&qe_target_info);
    if (qe3 != SGX_QL_SUCCESS) {
        fprintf(stderr, "error: sgx_qe_get_target_info failed: 0x%04x\n", qe3);
        sgx_destroy_enclave(enclave_id);
        return 1;
    }

    sgx_report_t report;
    memset(&report, 0, sizeof(report));
    uint32_t enclave_ret = 0xFFFFFFFFu;
    status = enclave_create_report(
        enclave_id, &enclave_ret, &qe_target_info, &report_data, &report);
    if (status != SGX_SUCCESS || enclave_ret != 0) {
        fprintf(stderr,
                "error: enclave_create_report failed: ecall=0x%04x enclave=0x%04x\n",
                status, enclave_ret);
        sgx_destroy_enclave(enclave_id);
        return 1;
    }

    uint32_t quote_size = 0;
    qe3 = sgx_qe_get_quote_size(&quote_size);
    if (qe3 != SGX_QL_SUCCESS || quote_size == 0) {
        fprintf(stderr, "error: sgx_qe_get_quote_size failed: 0x%04x\n", qe3);
        sgx_destroy_enclave(enclave_id);
        return 1;
    }

    uint8_t *quote_buffer = (uint8_t *)calloc(1, quote_size);
    if (quote_buffer == NULL) {
        fprintf(stderr, "error: out of memory\n");
        sgx_destroy_enclave(enclave_id);
        return 1;
    }
    qe3 = sgx_qe_get_quote(&report, quote_size, quote_buffer);
    if (qe3 != SGX_QL_SUCCESS) {
        fprintf(stderr, "error: sgx_qe_get_quote failed: 0x%04x\n", qe3);
        free(quote_buffer);
        sgx_destroy_enclave(enclave_id);
        return 1;
    }

    FILE *handle = fopen(out_path, "wb");
    if (handle == NULL) {
        fprintf(stderr, "error: cannot open %s for writing\n", out_path);
        free(quote_buffer);
        sgx_destroy_enclave(enclave_id);
        return 1;
    }
    const size_t written = fwrite(quote_buffer, 1, quote_size, handle);
    fclose(handle);
    free(quote_buffer);
    sgx_destroy_enclave(enclave_id);
    if (written != quote_size) {
        fprintf(stderr, "error: short write to %s\n", out_path);
        return 1;
    }

    printf("quote_size=%u\n", quote_size);
    printf("debug_flag=%d\n", (int)SGX_DEBUG_FLAG);
    printf("report_data=");
    for (size_t i = 0; i < REPORT_DATA_BYTES; ++i) {
        printf("%02x", report_data.d[i]);
    }
    printf("\n");
    return 0;
}
