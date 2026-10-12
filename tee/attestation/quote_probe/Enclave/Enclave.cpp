#include "Enclave_t.h"

#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

uint32_t enclave_create_report(const sgx_target_info_t *p_qe3_target,
                               const sgx_report_data_t *p_report_data,
                               sgx_report_t *p_report) {
    sgx_report_data_t report_data = {{0}};
    if (p_report_data != NULL) {
        report_data = *p_report_data;
    }
    /* sgx_create_report is provided by the trusted runtime and produces a
     * REPORT targeted at the quoting enclave. */
    return (uint32_t)sgx_create_report(p_qe3_target, &report_data, p_report);
}
