/*
 * Minimal untrusted host for testing an sgx-ra enclave in SGX simulation
 * mode (no SGX hardware, no quoting enclave).
 *
 *   sim_host ENCLAVE.signed.so
 *
 * It speaks the layer-1 executor protocol of docs/PROTOCOL.md §2 on
 * stdin/stdout, exactly like the blueprint App.cpp, except that the
 * announcement carries the raw 432-byte sgx_report_t (targeted at an
 * all-zero target info) instead of a DCAP quote:
 *
 *   S -> C  u32 BE 432 || report
 *   C -> S  u32 BE len || payload           (len 1..4096, else the host exits)
 *   S -> C  0x00 || u32 BE len || response  or a single 0x02 on ECALL failure
 *
 * Diagnostics go to stderr. For tests only: nothing here is attested.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sgx_urts.h"
#include "Enclave_u.h"

#define MAX_PAYLOAD 4096

static int read_exact(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(STDIN_FILENO, p, len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_exact(const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(STDOUT_FILENO, p, len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv)
{
    sgx_enclave_id_t eid = 0;
    sgx_target_info_t target;
    sgx_report_t report;
    uint32_t retval = 0;
    sgx_status_t status;
    int rc = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ENCLAVE.signed.so\n", argv[0]);
        return 2;
    }
    status = sgx_create_enclave(argv[1], 0, NULL, NULL, &eid, NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "sim_host: sgx_create_enclave failed: 0x%04x\n", status);
        return 1;
    }

    memset(&target, 0, sizeof(target));
    status = enclave_create_report(eid, &retval, &target, &report);
    if (status != SGX_SUCCESS || retval != 0) {
        fprintf(stderr, "sim_host: enclave_create_report failed: 0x%04x/0x%04x\n", status, retval);
        goto out;
    }
    uint32_t len_be = htonl(sizeof(report));
    if (write_exact(&len_be, 4) || write_exact(&report, sizeof(report)))
        goto out;

    for (;;) {
        uint8_t input[MAX_PAYLOAD], output[MAX_PAYLOAD];
        uint32_t msg_len, response_size = 0;
        sgx_status_t op_status = SGX_SUCCESS;

        if (read_exact(&msg_len, 4)) {
            rc = 0; /* EOF: session over */
            break;
        }
        msg_len = ntohl(msg_len);
        if (msg_len == 0 || msg_len > MAX_PAYLOAD) {
            fprintf(stderr, "sim_host: bad request length %u\n", msg_len);
            break;
        }
        if (read_exact(input, msg_len))
            break;
        memset(output, 0, sizeof(output));
        status = enclave_message(eid, &op_status, input, msg_len, output, &response_size);
        if (status != SGX_SUCCESS || op_status != SGX_SUCCESS || response_size > MAX_PAYLOAD) {
            uint8_t failure = 0x02;
            fprintf(stderr, "sim_host: enclave_message failed: 0x%04x/0x%04x\n", status, op_status);
            if (write_exact(&failure, 1))
                break;
            continue;
        }
        uint8_t ok = 0x00;
        uint32_t size_be = htonl(response_size);
        if (write_exact(&ok, 1) || write_exact(&size_be, 4) || write_exact(output, response_size))
            break;
    }
out:
    sgx_destroy_enclave(eid);
    return rc;
}
