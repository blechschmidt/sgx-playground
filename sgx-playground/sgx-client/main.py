import argparse
import logging
import os
import ssl
import socket
import struct
import subprocess
import typing

import intel_sgx_ra.attest
import intel_sgx_ra.css
import intel_sgx_ra.quote

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def recvall(sock: socket.socket, n: int) -> typing.Optional[bytes]:
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        logging.debug(f"Received packet: {packet}")
        if not packet:
            return None
        data += packet
    return data

def receive_message(socket: socket.socket):
    logging.debug("Waiting to receive message...")
    length_bytes = recvall(socket, 4)
    if length_bytes is None:
        return None
    length = struct.unpack(">I", length_bytes)[0]
    logging.debug(f"Message length: {length} bytes")
    logging.debug("Receiving message data...")
    data = recvall(socket, length)
    if data is None:
        raise Exception("Connection closed while reading message data")
    logging.debug(f"Received message data: {data}")
    return data

def send_receive(socket: socket.socket, msg) -> bytes:
    data = struct.pack(">I", len(msg)) + msg
    socket.sendall(data)
    logging.debug(f"Sent message: {msg}")
    status = recvall(socket, 1)
    logging.debug(f"Received status: {status}")
    if status != b"\x00":
        raise Exception("Operation failed with status: " + int(status[0]))
    length_bytes = recvall(socket, 4)
    length = struct.unpack(">I", length_bytes)[0]
    data = recvall(socket, length)
    return data

class CompilationStep:
    def __init__(self, command: str, workdir: str = ""):
        self.command = command
        self.workdir = workdir
    
    def compile(self):
        logging.info("Starting compilation step...")
        env = os.environ.copy()
        env["UID"] = str(os.getuid())
        env["GID"] = str(os.getgid())
        result = subprocess.run(self.command, shell=True, cwd=self.workdir, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Compilation failed with stderr: {result.stderr}")
            raise Exception("Compilation failed")
        logging.info("Compilation succeeded")
        

def main():
    parser = argparse.ArgumentParser(description="SGX Client")
    parser.add_argument("--host", type=str, default="sgx-playground.blechschmidt.io", required=False, help="Server hostname or IP address forwarding traffic to the enclave")
    parser.add_argument("--port", type=int, default=443, required=False, help="TLS tunnel port number")
    parser.add_argument("--loglevel", type=str, default="INFO", required=False, help="Logging level")
    parser.add_argument("--pccs-url", type=str, default="http://127.0.0.1:8080", required=False, help="PCCS URL for quote verification. Should be an HTTPS URL in production!")
    parser.add_argument("--gendata-path", type=str, default=os.path.join(SCRIPT_DIR, "../server/enclave.so.gendata"), required=False, help="Path to gendata file after compilation")
    parser.add_argument("--compile-command", type=str, default="docker compose run --build make", required=False, help="Command to compile the SGX gendata artifact")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.loglevel.upper(), None), filename='/dev/stderr')

    CompilationStep(command=args.compile_command, workdir=".").compile()

    context = ssl.create_default_context()

    with socket.create_connection((args.host, args.port)) as sock:
        with context.wrap_socket(sock, server_hostname=args.host) as ssock:
            print(f"Connected to {args.host}:{args.port} via TLS")
            
            quote = receive_message(ssock)
            logging.info(f"Received quote of length {len(quote)} bytes")
            remote_quote = intel_sgx_ra.quote.Quote.from_bytes(quote)
            if not intel_sgx_ra.attest.verify_quote(quote=remote_quote, pccs_url=args.pccs_url):
                # Should never happen because verify_quote raises on failure, but still...
                raise Exception("Quote verification failed")
            logging.info("Quote verification succeeded")

            local_css = intel_sgx_ra.css.gendata_from_file(args.gendata_path)
            local_mrenclave = bytes(local_css.body.enclave_hash)
            assert bytes(local_css.header.header) == bytes.fromhex("06000000E100000000000100")

            if remote_quote.report_body.mr_enclave != local_mrenclave:
                raise Exception("MRENCLAVEs do not match! Local MRENCLAVE is %s but remote MRENCLAVE is %s" % (local_mrenclave.hex(), remote_quote.report_body.mr_signer.hex()))

            print("Remote code is identical to local code (MRENCLAVE match)")

            reply = send_receive(ssock, b"Hello, SGX server!")

            print("Reply received from server: ", reply.decode())

if __name__ == "__main__":
    main()
