# Intel SGX Playground

A remote attestation PoC implementation with Intel SGX.

## Ready-to-use remote attestation example

This is not a production-grade project. It just serves as a minimal example (PoC) for performing remote attestation, which is the process of proving that a remote SGX enclave is running certain code (i.e. machine code you are able reproduce locally) through the `MRENCLAVE` value.

In general, this is done as follows:
1. The code and initial data are loaded into the enclave and are fixed. A hash over this initial configuration is computed (`MRENCLAVE`).
2. Upon a request (`sgx_create_report`), a "quote" is generated. This quote can be verified through the provisioning certificate caching service contains a signature signed with an Intel key (roughly) over the following:
    - a hash over the signer's public key (`MRSIGNER` value, currently unused/unverified in this PoC)
    - a `report_data` field, which in the future will be the hash of a public key whose private key is generated inside the enclave, which in turn can be used to establish a trusted channel into the enclave (currently, it is unused in this PoC)
    - a hash over the code running inside the enclave along with initial enclave configuration (`MRENCLAVE`, verified in this PoC)

## Quickstart

1. Get an Intel API key from [here](https://api.portal.trustedservices.intel.com/provisioning-certification).

2. First install `docker compose`. Note that there is `docker-compose` and `docker compose`, where the latter is available as `docker-compose-v2` in the
`apt` repositories.

3. Clone the repository and `cd` into it. Make sure you are in the top-level directory of the repository when running `docker compose` commands.

4. Prepare the PCCS service. This command will generate a configuration file, as well as CA and server certificates, based the provided API key.
   ```
   API_KEY=<YOUR_API_KEY> docker compose run prepare-pccs
   ```

5. As the `pccs` service in the `compose.yaml` is configured to use host networking, the following command will spawn HTTP and HTTPS servers on ports 8080 and 8081, respectively, in the background:
   ```
   docker compose run -d pccs
   ```

6. Optionally verify that the PCCS server is running:
   ```
   curl -v '127.0.0.1:8080/sgx/certification/v4/pckcrl?ca=processor&encoding=pem'
   ```

7. Run the SGX client:
   ```
   docker compose run --build verify
   ```

   You should see an output similar to the following:
   ```
   INFO:root:Starting compilation step...
   INFO:root:Compilation succeeded
   Connected to sgx-playground.blechschmidt.io:443 via TLS
   INFO:root:Received quote of length 4734 bytes
   INFO:intel-sgx-ra:[   OK ] No SGX debug mode
   INFO:intel-sgx-ra:[   OK ] Certification chain
   INFO:intel-sgx-ra:[   OK ] TCB signature
   INFO:intel-sgx-ra:[   OK ] Quote signature
   INFO:intel-sgx-ra:[   OK ] QE report signature
   INFO:root:Quote verification succeeded
   Remote code is identical to local code (MRENCLAVE match)
   Reply received from server:  Hello, SGX server!
   ```

   Congratulations! You have just performed your first remote attestation and verified that the code
   in the `server/Enclave` directory of this repository is running remotely inside an enclave.

   The `verify` service has (reproducibly) built the shared object that is running remotely.


## Components

### Provisioning Certificate Caching Service (PCCS)

First, set up configuration files for the certificate caching service. For this, you will need an API key from Intel, which you can obtain [here](https://api.portal.trustedservices.intel.com/provisioning-certification).

```
API_KEY=<YOUR_API_KEY> docker compose run --build prepare-pccs
```

An HTTP server at `http://127.0.0.1:8080` will be spawned. As the compose file uses host networking, the server will be accessible from the host system.

### Server Enclave Code (/server/Enclave)

The enclave code currently consists of a minimal echo server. It provides two `ECALL` functions:
- `enclave_create_report`, which is called by the app code to generate a quote for remote attestation
- `enclave_message`, which is a communication function called by the app. This function currently just
replies with the input, i.e. functions as an echo server.

### Server App Code (/server/App)

The code that interacts with the enclave, requests the quoting enclave to generate a quote and then
forwards binary chunks on stdin to the `enclave_message` function, which generates responses inside the enclave.
The responses are then printed to stdout.

### Interacting and Verifying Component (sgx-client)

This is a component that can run anywhere. It establishes a TLS tunnel to the server.
(Note that the tunnel comes without any protection through the enclave itself.)

The component comes with the following CLI, which is exposed through the `verify` service in the `Dockerfile`:
```
usage: main.py [-h] [--host HOST] [--port PORT] [--loglevel LOGLEVEL] [--pccs-url PCCS_URL] [--gendata-path GENDATA_PATH] [--compile-command COMPILE_COMMAND]

SGX Client

options:
  -h, --help            show this help message and exit
  --host HOST           Server hostname or IP address forwarding traffic to the enclave
  --port PORT           TLS tunnel port number
  --loglevel LOGLEVEL   Logging level
  --pccs-url PCCS_URL   PCCS URL for quote verification. Should be an HTTPS URL in production!
  --gendata-path GENDATA_PATH
                        Path to gendata file after compilation
  --compile-command COMPILE_COMMAND
                        Command to compile the SGX gendata artifact
```
It is supplied with a `--compile-command`, which in practice is a call to `make` compiling the applications in the `server` directory of this repository.
As part of the compilation process, a gendata file is generated as a compilation artifact. The structure of this artifact is also referred to as code
signing structure (CSS). Next to other information, it contains the `MRENCLAVE` value of the produced code and can in turn be matched against the `MRENCLAVE` command of the remote application.

### Files

<!-- Generation command: tree -a . --gitignore -I .git -->
```
.
├── compose.yaml------------------| Docker Compose file providing PCCS server, enclave builder and remote verifier
├── config------------------------|
│   ├── .gitignore----------------|
│   ├── nginx---------------------|
│   │   └── proxy.conf------------| nginx proxy configuration to locally expose the PCCS through HTTP
│   └── server--------------------|
│       └── stunnel.conf----------| stunnel configuration file to expose the server application through HTTPS
├── containers--------------------|
│   ├── Dockerfile.build----------| Dockerfile with Intel SGX SDK and DCAP for building enclave and accompanying app
│   ├── Dockerfile.pccs-----------| Dockerfile for running the PCCS server
│   └── Dockerfile.verify-quote---|
├── README.md---------------------|
├── scripts-----------------------|
│   └── pccs----------------------|
│       ├── prepare---------------| Script that generates a self-signed CA and a certificate for the PCCS server
│       └── run-------------------| Script that starts the PCCS server (used in Dockerfile.pccs)
├── server------------------------|
│   ├── App-----------------------| enclave-accompanying application
│   │   ├── App.cpp---------------| code of the server application communicating with the enclave through `ECALL`s
│   │   ├── .gitignore------------|
│   ├── Enclave-------------------|
│   │   ├── Enclave.config.xml----| enclave configuration (e.g. maximum stack and heap sizes)
│   │   ├── Enclave.cpp-----------| enclave code
│   │   ├── Enclave.edl-----------| enclave ECALL definitions for Edger8r (code generation tool for copying untrusted buffers into the enclave)
│   │   ├── Enclave.lds-----------| enclave linker script defining exported symbols
│   │   └── .gitignore------------|
│   ├── .gitignore----------------|
│   └── Makefile------------------| Makefile for enclave and accompanying application
└── sgx-client--------------------|
    ├── main.py-------------------| client code that performs remote attestation verification 
    ├── pyproject.toml------------|
    ├── .python-version-----------|
    ├── uv.lock-------------------| Pinned dependencies for uv (Python package manager)
    └── .venv---------------------|
```


### TODOS

- Rust implementation
- Sealing PoC
- Establishment of secure communication channel into the enclave (using the report data field to pin a hash of public key material)
- Improved reproducibility with Nix
- Implement `MRSIGNER` verification
- Server app containerization

### Resources

- https://sys.cs.fau.de/extern/lehre/ws22/akss/material/intel-sgx.pdf
- https://download.01.org/intel-sgx/sgx-linux/2.8/docs/Intel_SGX_Developer_Reference_Linux_2.8_Open_Source.pdf
- https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf
- https://actually.fyi/posts/sgx/
- https://github.com/Cosmian/intel-sgx-ra
