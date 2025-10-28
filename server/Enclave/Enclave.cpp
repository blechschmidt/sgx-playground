#include "Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "string.h"

bool generated_key = false;
sgx_ecc_state_handle_t ecc_handle;
sgx_report_data_t report_data = { 0 };
sgx_ec256_private_t privkey;
sgx_ec256_public_t pubkey;
sgx_sha256_hash_t hash;
uint8_t output[0xffff];

sgx_status_t generate_key_pair() {
    sgx_status_t status;

    if (!generated_key) {
        status = sgx_ecc256_open_context(&ecc_handle);
        if (status != SGX_SUCCESS) {
            return status;
        }
        generated_key = true;
    }

    sgx_sha_state_handle_t sha_handle;
    status = sgx_sha256_init(&sha_handle);
    if (status != SGX_SUCCESS) {
        return status;
    }

    status = sgx_sha256_update((uint8_t*)&pubkey, sizeof(pubkey), sha_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup_sha_context;
    }

    status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*)report_data.d);
    if (status != SGX_SUCCESS) {
        goto cleanup_sha_context;
    }

    status = sgx_ecc256_create_key_pair(&privkey, &pubkey, ecc_handle);

cleanup_sha_context:
    sgx_sha256_close(sha_handle);
    return status;
}

sgx_status_t enclave_message(
    const uint8_t* p_data,
    uint32_t data_size,
    uint8_t* p_response,
    uint32_t* p_response_size)
{
    sgx_status_t status;

    if (data_size > 4096 || p_response_size == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    *p_response_size = data_size;
    for (uint32_t i = 0; i < data_size; i++) {
        p_response[i] = p_data[i]; // Simple operation for demonstration
    }
    return SGX_SUCCESS;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{
    sgx_status_t status = generate_key_pair();
    if (status != SGX_SUCCESS) 
	return status;

    // Generate the report for the app_enclave
    sgx_status_t sgx_error = sgx_create_report(p_qe3_target, &report_data, p_report);

    return sgx_error;
}
