/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * File: app.cpp
 *
 * Description: Sample application to
 * demonstrate the usage of quote generation.
 */


#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h> // ntohl

#include <vector>
#include <fstream>
#include <getopt.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"
#if SGX_QPL_LOGGING
#include "sgx_default_quote_provider.h"
#endif

#include "Enclave_u.h"

#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#define ENCLAVE_PATH "enclave.signed.so"
typedef quote3_error_t (*sgx_qpl_clear_cache_func_t)(uint32_t);

using namespace std;

#define log(msg, ...)                             \
    do                                            \
    {                                             \
        fprintf(stderr, "[APP] " msg "\n", ##__VA_ARGS__); \
        fflush(stderr);                           \
    } while (0)


bool create_app_enclave_report(sgx_target_info_t &qe_target_info, sgx_report_t *app_report, sgx_enclave_id_t *eid)
{
        bool ret = true;
        uint32_t retval = 0;
        sgx_status_t sgx_status = SGX_SUCCESS;
        int launch_token_updated = 0;
        sgx_launch_token_t launch_token = { 0 };

        sgx_status = sgx_create_enclave(ENCLAVE_PATH,
                SGX_DEBUG_FLAG,
                &launch_token,
                &launch_token_updated,
                eid,
                NULL);
        if (SGX_SUCCESS != sgx_status) {
                log("Error: call sgx_create_enclave fail [%s], SGXError:%04x.", __FUNCTION__, sgx_status);
                ret = false;
                goto CLEANUP;
        }


        sgx_status = enclave_create_report(*eid,
                &retval,
                &qe_target_info,
                app_report);
        if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
                log("Error: Call to get_app_enclave_report() failed");
                ret = false;
                goto CLEANUP;
        }

CLEANUP:
        return ret;
}

void qpl_logger(sgx_ql_log_level_t level, const char *message)
{
    const string pre_qcnl = "[QCNL]";
    const string pre_qpl = "[QPL]";
    string msg(message);
    if (level == SGX_QL_LOG_INFO)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " Info: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "Info: ");
        else
            msg.insert(0, "Info: ");
        printf("%s", msg.c_str());
    }
    else if (level == SGX_QL_LOG_ERROR)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " Error: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "Error: ");
        else
            msg.insert(0, "Error: ");
        printf("%s", msg.c_str());
    } else if (level == SGX_QL_LOG_DEBUG)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " DEBUG: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "DEBUG: ");
        else
            msg.insert(0, "DEBUG: ");
        printf("%s", msg.c_str());
    }
    else if (level == SGX_QL_LOG_TRACE)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " TRACE: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "TRACE: ");
        else
            msg.insert(0, "TRACE: ");
        printf("%s", msg.c_str());
    }
}

vector<uint8_t> readBinaryContent(const string& filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        log("Error: Unable to open file %s", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char*>(retVal.data()), fileSize);
    file.close();
    return retVal;
}

bool writeBinaryContent(const string& filePath, const vector<uint8_t>& data)
{
    ofstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        log("Error: Unable to open file %s for writing", filePath.c_str());
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

void usage() {
    printf("Usage: app [options]\n");
    printf("Options:\n");
    printf("  -t, --target-info <path/to/target_info>   Use target_info in the file instead of generating it by `sgx_qe_get_target_info` fucntion.\n");
    printf("  -c, --clear-cache TYPE                    Clear QPL's cache of TYPE (cert|collateral|all)\n");
    printf("  -q, --qe-target-info                      Path to QE target info output\n");
}

ssize_t read_all(uint8_t *buffer, size_t to_read, FILE *f) {
    size_t read = 0;
    while (read < to_read) {
        size_t read_chunk = to_read - read;
        size_t r = fread(buffer + read, read_chunk, 1, f);
        read += r;
        if (r < read_chunk) {
            if (feof(f)) {
                return read;
            }
            else if (ferror(f)) {
                return -1;
            } else {
                // should not reach here
                return -1;
            }
        }
    }
    return read;
}

ssize_t write_all(uint8_t *buffer, size_t to_write, int fd) {
    size_t written = 0;
    while (written < to_write) {
        size_t write_chunk = to_write - written;
        ssize_t w = write(fd, buffer + written, write_chunk);
        if (w < 0) {
            return w;
        }
        written += w;
    }
    return written;
}

typedef enum {
    STATUS_OK = 0,
    MESSAGE_TOO_SHORT = 1,
    ENCLAVE_COMMUNICATION_FAILURE = 2
} comunication_state_t;

int main(int argc, char* argv[])
{

    int ret = 0;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;
    sgx_target_info_t qe_target_info = { 0 };
    sgx_report_t app_report = { 0 };
    sgx_quote3_t *p_quote = NULL;
    sgx_ql_auth_data_t *p_auth_data = NULL;
    sgx_ql_ecdsa_sig_data_t *p_sig_data = NULL;
    sgx_ql_certification_data_t *p_cert_data = NULL;
    sgx_enclave_id_t eid = 0;
    FILE *fptr = NULL;
    bool is_out_of_proc = false;
    int option_index = 0;
    int c = 0;
    bool target_info_provided = false;
    string qpl_library_path = "";
    string output_qe_info_path = "";


    uint32_t message_size;
    size_t read = 0;
    uint8_t input[4096];
    uint8_t output[4096];
    bool read_input = false;
    uint8_t status = 0;
    uint8_t communication_state = STATUS_OK;
    sgx_status_t op_status = SGX_SUCCESS;
    sgx_status_t result = SGX_SUCCESS;
    size_t to_read = 0;
    size_t no_read = 0;
    uint32_t response_size;

    char *out_of_proc = getenv(SGX_AESM_ADDR);
    if(out_of_proc)
        is_out_of_proc = true;

    struct option long_options[] = {
        {"target-info", required_argument, 0, 't'},
        {"clear-cache", required_argument, 0, 'c'},
        {"qe-target-info", required_argument, 0, 'q'},
        {0, 0, 0, 0}
    };

#if SGX_QPL_LOGGING
    sgx_ql_set_logging_callback(qpl_logger, static_cast<sgx_ql_log_level_t>(SGX_QPL_LOGGING - 1));
#endif

#ifdef SGX_TRACE_LOGGING
    sgx_ql_set_trace_callback(qpl_logger, (sgx_ql_log_level_t)(SGX_TRACE_LOGGING - 1));
#endif

    // There 2 modes on Linux: one is in-proc mode, the QE3 and PCE are loaded within the user's process.
    // the other is out-of-proc mode, the QE3 and PCE are managed by a daemon. If you want to use in-proc
    // mode which is the default mode, you only need to install libsgx-dcap-ql. If you want to use the
    // out-of-proc mode, you need to install libsgx-quote-ex as well. This sample is built to demo both 2
    // modes, so you need to install libsgx-quote-ex to enable the out-of-proc mode.
    if(!is_out_of_proc)
    {
        // Following functions are valid in Linux in-proc mode only.
        log("Info: sgx_qe_set_enclave_load_policy is valid in in-proc mode only and it is optional: the default enclave load policy is persistent");
        log("Info: set the enclave load policy as persistent");
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
            log("Error: set enclave load policy error: 0x%04x", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_IDE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_IDE_PATH, "/usr/lib64/libsgx_id_enclave.signed.so.1")) {
                log("Error: set PCE/QE3/IDE directory error.");
                ret = -1;
                goto CLEANUP;
            }
        }


        qpl_library_path = "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1";
        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, qpl_library_path.c_str());
        if (SGX_QL_SUCCESS != qe3_ret) {
            qpl_library_path = "/usr/lib64/libdcap_quoteprov.so.1";
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, qpl_library_path.c_str());
            if(SGX_QL_SUCCESS != qe3_ret) {
                qpl_library_path = "";
                // Ignore the error, because user may want to get cert type=3 quote
                log("Warning: Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.");
            }
        }
    }

    while ((c = getopt_long(argc, argv, "t:c:q:", long_options, &option_index)) != -1) {
        switch (c) {
            case 't':
            {
                printf("\nRead target_info:");
                std::vector<uint8_t> target_info = readBinaryContent(optarg);
                if (target_info.empty()) {
                    usage();
                    ret = -1;
                    goto CLEANUP;
                }
                printf(" path: %s:", optarg);
                if (sizeof(qe_target_info) != target_info.size()) {
                    printf("Error: Invalid target info file.");
                    ret = -1;
                    goto CLEANUP;
                }
                memcpy(&qe_target_info, target_info.data(), sizeof(qe_target_info));
                target_info_provided = true;
                break;
            }
            case 'c':
            {
                uint32_t clear_cache_type = 0;
                if (strcasecmp(optarg, "cert") == 0) {
                    clear_cache_type = SGX_QPL_CACHE_CERTIFICATE;
                }
                else if (strcasecmp(optarg, "collateral") == 0) {
                    clear_cache_type = SGX_QPL_CACHE_QV_COLLATERAL;
                }
                else if (strcasecmp(optarg, "all") == 0) {
                    clear_cache_type = SGX_QPL_CACHE_CERTIFICATE | SGX_QPL_CACHE_QV_COLLATERAL;
                }
                else {
                    printf("Error: Unrecognized value for --clear-cache.\n");
                    ret = -1;
                    goto CLEANUP;
                }

                if (!qpl_library_path.empty()) {
                    void* handle = dlopen(qpl_library_path.c_str(), RTLD_LAZY);
                    if (!handle) {
                        printf("Failed to load shared library %s: %s\n", qpl_library_path.c_str(), dlerror());
                        ret = -1;
                        goto CLEANUP;
                    }
                    // Get the function pointer
                    sgx_qpl_clear_cache_func_t sgx_qpl_clear_cache_func = reinterpret_cast<sgx_qpl_clear_cache_func_t>(
                        dlsym(handle, "sgx_qpl_clear_cache")
                    );
                    if (sgx_qpl_clear_cache_func) {
                        sgx_qpl_clear_cache_func(clear_cache_type);
                    }
                    dlclose(handle);
                }
                break;
            }
            case 'q':
            {
                output_qe_info_path = optarg;
                break;
            }
            default:
                usage();
                return 0;
        }
    }

    if (!target_info_provided) {
        log("Step1: Call sgx_qe_get_target_info:");
        qe3_ret = sgx_qe_get_target_info(&qe_target_info);
        if (SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
        if (!output_qe_info_path.empty()) {
            log("Info: Writing QE target info to file %s", output_qe_info_path.c_str());
            vector<uint8_t> qe_target_info_data(sizeof(qe_target_info));
            memcpy(qe_target_info_data.data(), &qe_target_info, sizeof(qe_target_info));
            if (!writeBinaryContent(output_qe_info_path, qe_target_info_data)) {
                log("Error: Unable to write QE target info to file %s", output_qe_info_path.c_str());
                ret = -1;
                goto CLEANUP;
            }
        }
        log("succeed!");
    }

    log("Step2: Call create_app_report");
    if(true != create_app_enclave_report(qe_target_info, &app_report, &eid)) {
        log("Info: Call to create_app_report() failed");
        ret = -1;
        goto CLEANUP;
    }

    fptr = fopen("report.dat","wb");
    if( fptr ) {
        fwrite(&app_report, sizeof(app_report), 1, fptr);
        fclose(fptr);
    }

    log("Step3: Call sgx_qe_get_quote_size");
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        log("Error: sgx_qe_get_quote_size error 0x%04x", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        log("Info: Couldn't allocate quote_buffer");
        ret = -1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    log("Step4: Call sgx_qe_get_quote");
    qe3_ret = sgx_qe_get_quote(&app_report,
        quote_size,
        p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        log( "Error: sgx_qe_get_quote got error 0x%04x", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    p_quote = (sgx_quote3_t*)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    log("cert_key_type = 0x%x", p_cert_data->cert_key_type);

    fptr = fopen("quote.dat","wb");
    if( fptr )
    {
        fwrite(p_quote, quote_size, 1, fptr);
        fclose(fptr);
    }

    message_size = htonl(quote_size);
    write_all((uint8_t*)&message_size, sizeof(message_size), 1);
    write_all(p_quote_buffer, quote_size, 1);

    while(true) {
        to_read = read_input ? message_size : sizeof(message_size);
        no_read = read_all(input, to_read, stdin);
        if (no_read <= 0) {
            break;
        }
        if (!read_input) {
            message_size = ntohl(*(uint32_t*)input);
            log("Info: Received message of size %u", message_size);
            read_input = true;
        } else {
            read_input = false;
            if (no_read < message_size) {
                communication_state = MESSAGE_TOO_SHORT;
                log("Error: Message too short, expected %u bytes, got %zu bytes", message_size, no_read);
                write_all(&communication_state, 1, 1);
                continue;
            }
            log("Info: Sending message of size %u to enclave", message_size);

            result = enclave_message(eid, &op_status, input, message_size, output, &response_size);
            if (SGX_SUCCESS != result || SGX_SUCCESS != op_status) {
                communication_state = ENCLAVE_COMMUNICATION_FAILURE;
                log("Error: Enclave communication failure, sgx_status_t=0x%04x, op_status=0x%04x", result, op_status);
                write_all(&communication_state, 1, 1);
                continue;
            }
            log("Info: Enclave processed message successfully, response size %u", response_size);

            communication_state = STATUS_OK;
            write_all(&communication_state, 1, 1);
            response_size = htonl(response_size);
            write_all((uint8_t*)&response_size, sizeof(response_size), 1);
            response_size = ntohl(response_size);
            write_all(output, response_size, 1);
        }
    }


    sgx_destroy_enclave(eid);

    if( !is_out_of_proc )
    {
        log("Info: sgx_qe_cleanup_by_policy is valid in in-proc mode only.");
        log("Info: Clean up the enclave load policy");
        qe3_ret = sgx_qe_cleanup_by_policy();
        if(SGX_QL_SUCCESS != qe3_ret) {
            log("Error: cleanup enclave load policy with error 0x%04x", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
    }

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
}
