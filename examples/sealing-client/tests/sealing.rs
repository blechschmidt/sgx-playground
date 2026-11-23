//! End-to-end tests of the sealing example: `sealing-client` against a
//! real `sealing-enclave` image behind the Rust host (`echo-host-app`, any
//! sgx-ra host binary works) with `--sealed-dir`.
//!
//! Two groups:
//!
//! * `sim_*`: SGX **simulation** (the SDK's software sealing keys, raw
//!   unsigned report). Always `#[ignore]`d; run them with
//!
//!   ```sh
//!   enclave-sys/build.sh --mode SIM --crate sealing-enclave \
//!       --edl enclave-sys/sealed-storage/Enclave.edl --out target/enclave/sealing-enclave-sim
//!   SGX_SDK=… SGX_MODE=SIM cargo build -p echo-host-app --features sgx
//!   SGX_RA_SIM_HOST_BIN="LD_LIBRARY_PATH=$SGX_SDK/lib64 target/debug/echo-host-app" \
//!   SGX_RA_SEALING_SIM_DIR=target/enclave/sealing-enclave-sim \
//!   cargo test -p sealing-client --test sealing -- --ignored sim_
//!   ```
//!
//! * `hw_*`: SGX **hardware** with DCAP: `#[ignore]`d when the build
//!   machine has no `/dev/sgx_enclave` (see `build.rs`). They need
//!   `SGX_RA_HW_HOST_BIN` (a host built with `--features sgx`, SGX_MODE=HW),
//!   `SGX_RA_SEALING_HW_DIR` (the HW build output: `enclave.signed.so`,
//!   `enclave.so.gendata`) and optionally `SGX_RA_PCCS_URL`.

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const CLIENT: &str = env!("CARGO_BIN_EXE_sealing-client");

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sealing-e2e-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set (see the module docs)"))
}

fn mrenclave(dir: &str) -> String {
    let path = Path::new(dir);
    fs::read_to_string(path.join("mrenclave.hex"))
        .or_else(|_| fs::read_to_string(path.join("MRENCLAVE.txt")))
        .expect("mrenclave.hex / MRENCLAVE.txt in the enclave directory")
        .trim()
        .to_owned()
}

/// Runs the client against a fresh simulation host instance.
fn sim(sealed_dir: Option<&Path>, args: &[&str]) -> Output {
    let dir = env("SGX_RA_SEALING_SIM_DIR");
    let mut host = format!(
        "{} --quoter unattested-report --enclave {dir}/enclave.signed.so",
        env("SGX_RA_SIM_HOST_BIN")
    );
    if let Some(d) = sealed_dir {
        host.push_str(&format!(" --sealed-dir {}", d.display()));
    }
    let output = Command::new(CLIENT)
        .args([
            "--simulation-host",
            &host,
            "--expected-mrenclave",
            &mrenclave(&dir),
        ])
        .args(args)
        .output()
        .expect("run sealing-client");
    eprintln!(
        "sealing-client {args:?}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// All sealed blobs below `dir`.
fn blobs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for ns in fs::read_dir(dir).unwrap() {
        for f in fs::read_dir(ns.unwrap().path()).unwrap() {
            out.push(f.unwrap().path());
        }
    }
    out
}

#[test]
#[ignore = "needs the SGX simulation build (see module docs)"]
fn sim_identity_persists_across_restarts() {
    let s = Scratch::new("persist");
    let (sealed, pin) = (s.path("sealed"), s.path("enclave.pin"));
    let pin_arg = pin.to_str().unwrap();

    let first = sim(Some(&sealed), &["identity", "--pin", pin_arg]);
    assert!(first.status.success());
    assert!(stderr(&first).contains("created and sealed"));
    assert!(stderr(&first).contains("pinned it"));
    let key = stdout(&first);
    assert_eq!(key.len(), 64);
    assert_eq!(fs::read_to_string(&pin).unwrap().trim(), key);

    // One blob, in one namespace: sgx_sealed_data_t (560) + the 32-byte
    // secret + authenticated data naming purpose, policy, slot and lk_pub.
    // The public key is visible to the host by design; the secret is not.
    let files = blobs(&sealed);
    assert_eq!(files.len(), 1, "{files:?}");
    let blob = fs::read(&files[0]).unwrap();
    assert_eq!(blob.len(), 560 + 32 + 34 + 1 + 1 + 4 + 32);
    assert!(blob.windows(32).any(|w| Hex(w) == key.as_str()));

    // A new enclave instance (new channel key, new quote) restores it.
    let second = sim(Some(&sealed), &["identity", "--pin", pin_arg]);
    assert!(second.status.success());
    assert!(stderr(&second).contains("restored from sealed storage"));
    assert!(stderr(&second).contains("matches the key pinned"));
    assert_eq!(stdout(&second), key);
    assert_eq!(
        fs::read(&files[0]).unwrap(),
        blob,
        "restoring must not rewrite the blob"
    );
}

#[test]
#[ignore = "needs the SGX simulation build (see module docs)"]
fn sim_without_storage_the_identity_is_ephemeral() {
    let s = Scratch::new("ephemeral");
    let pin = s.path("enclave.pin");
    let a = sim(None, &["identity", "--pin", pin.to_str().unwrap()]);
    let b = sim(None, &["identity", "--pin", pin.to_str().unwrap()]);
    assert!(a.status.success() && b.status.success());
    assert!(stderr(&a).contains("ephemeral"));
    assert_ne!(stdout(&a), stdout(&b));
    assert!(!pin.exists(), "ephemeral keys must not be pinned");
}

#[test]
#[ignore = "needs the SGX simulation build (see module docs)"]
fn sim_tampered_or_lost_identity_fails_closed() {
    let s = Scratch::new("tamper");
    let (sealed, pin) = (s.path("sealed"), s.path("enclave.pin"));
    let pin_arg = pin.to_str().unwrap();
    assert!(
        sim(Some(&sealed), &["identity", "--pin", pin_arg])
            .status
            .success()
    );
    let file = blobs(&sealed).remove(0);
    let good = fs::read(&file).unwrap();

    // Tampered blob: the enclave refuses (no silent rotation) and leaves it.
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    fs::write(&file, &bad).unwrap();
    let out = sim(Some(&sealed), &["identity", "--pin", pin_arg]);
    assert_eq!(out.status.code(), Some(3), "enclave error exit code");
    assert!(stderr(&out).contains("long-term identity unavailable"));
    assert_eq!(fs::read(&file).unwrap(), bad);

    // Restoring the genuine blob restores the key.
    fs::write(&file, &good).unwrap();
    assert!(
        sim(Some(&sealed), &["identity", "--pin", pin_arg])
            .status
            .success()
    );

    // Storage wiped: the enclave creates a new key, the pin catches it.
    fs::remove_dir_all(&sealed).unwrap();
    let out = sim(Some(&sealed), &["identity", "--pin", pin_arg]);
    assert_eq!(out.status.code(), Some(4), "pin mismatch exit code");
    assert!(stderr(&out).contains("long-term identity changed"));
}

#[test]
#[ignore = "needs the SGX simulation build (see module docs)"]
fn sim_seal_and_unseal_across_instances() {
    let s = Scratch::new("data");
    let (input, blob, output) = (s.path("in"), s.path("blob"), s.path("out"));
    let secret: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    fs::write(&input, &secret).unwrap();
    let p = |p: &Path| p.to_str().unwrap().to_owned();

    let sealed = sim(
        None,
        &["seal", "--input", &p(&input), "--output", &p(&blob)],
    );
    assert!(sealed.status.success());
    let blob_bytes = fs::read(&blob).unwrap();
    assert!(!blob_bytes.windows(64).any(|w| w == &secret[..64]));

    // Another instance of the same enclave opens it.
    let opened = sim(
        None,
        &["unseal", "--input", &p(&blob), "--output", &p(&output)],
    );
    assert!(opened.status.success());
    assert_eq!(fs::read(&output).unwrap(), secret);

    // Any modification is detected.
    for index in [0usize, 4, 600, blob_bytes.len() - 1] {
        let mut bad = blob_bytes.clone();
        bad[index] ^= 0x40;
        fs::write(&blob, &bad).unwrap();
        let out = sim(None, &["unseal", "--input", &p(&blob)]);
        assert_eq!(out.status.code(), Some(3), "byte {index}");
    }
}

/// `Hex` for the blob scan above.
struct Hex<'a>(&'a [u8]);

impl PartialEq<&str> for Hex<'_> {
    fn eq(&self, other: &&str) -> bool {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        hex == *other
    }
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

/// A host app listening on a free local port; killed on drop.
struct HwHost {
    child: Child,
    port: u16,
}

impl HwHost {
    fn start(sealed: &Path) -> Self {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = env("SGX_RA_SEALING_HW_DIR");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "exec {} --enclave {dir}/enclave.signed.so --listen 127.0.0.1:{port} --sealed-dir {}",
                env("SGX_RA_HW_HOST_BIN"),
                sealed.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the hardware host");
        let deadline = Instant::now() + Duration::from_secs(60);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            if let Ok(Some(status)) = child.try_wait() {
                let mut err = String::new();
                child.stderr.take().unwrap().read_to_string(&mut err).ok();
                panic!("host exited with {status}: {err}");
            }
            assert!(Instant::now() < deadline, "host did not start listening");
            std::thread::sleep(Duration::from_millis(200));
        }
        Self { child, port }
    }

    fn client(&self, args: &[&str]) -> Output {
        let dir = env("SGX_RA_SEALING_HW_DIR");
        let mut cmd = Command::new(CLIENT);
        cmd.args(["--plaintext", "--port", &self.port.to_string()])
            .args(["--gendata-path", &format!("{dir}/enclave.so.gendata")]);
        if let Ok(url) = std::env::var("SGX_RA_PCCS_URL") {
            cmd.args(["--pccs-url", &url]);
        }
        let out = cmd.args(args).output().expect("run sealing-client");
        eprintln!("sealing-client {args:?}: {}\n{}", out.status, stderr(&out));
        out
    }
}

impl Drop for HwHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[cfg_attr(not(sgx_hw), ignore = "needs SGX hardware (/dev/sgx_enclave)")]
fn hw_identity_persists_across_host_restarts() {
    let s = Scratch::new("hw-persist");
    let (sealed, pin) = (s.path("sealed"), s.path("enclave.pin"));
    let pin_arg = pin.to_str().unwrap();
    let first = {
        let host = HwHost::start(&sealed);
        let out = host.client(&["identity", "--pin", pin_arg]);
        assert!(out.status.success());
        assert!(stderr(&out).contains("DCAP quote verified"));
        stdout(&out)
    };
    // A restarted host process, fresh enclave instances: same key.
    let host = HwHost::start(&sealed);
    for _ in 0..2 {
        let out = host.client(&["identity", "--pin", pin_arg]);
        assert!(out.status.success());
        assert!(stderr(&out).contains("matches the key pinned"));
        assert_eq!(stdout(&out), first);
    }
}

#[test]
#[cfg_attr(not(sgx_hw), ignore = "needs SGX hardware (/dev/sgx_enclave)")]
fn hw_seal_unseal_roundtrip_and_tamper_detection() {
    let s = Scratch::new("hw-data");
    let host = HwHost::start(&s.path("sealed"));
    let (input, blob, output) = (s.path("in"), s.path("blob"), s.path("out"));
    fs::write(&input, b"hardware-sealed secret").unwrap();
    let p = |p: &Path| p.to_str().unwrap().to_owned();
    assert!(
        host.client(&["seal", "--input", &p(&input), "--output", &p(&blob)])
            .status
            .success()
    );
    assert!(
        host.client(&["unseal", "--input", &p(&blob), "--output", &p(&output)])
            .status
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), b"hardware-sealed secret");
    let mut bad = fs::read(&blob).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    fs::write(&blob, &bad).unwrap();
    assert_eq!(
        host.client(&["unseal", "--input", &p(&blob)]).status.code(),
        Some(3)
    );
}
