//! Local reproducible build of the enclave: the client's source of truth
//! for the expected MRENCLAVE.
//!
//! [`ReproducibleBuild`] runs
//!
//! ```text
//! docker build -f <Dockerfile> --output type=local,dest=<dir> [--build-arg K=V]… <context>
//! ```
//!
//! (or the same with `podman`) and reads the `enclave.so.gendata` the build
//! exports. Docker without the buildx plugin cannot use `--output`; then
//! the classic builder builds a tagged image and the artefacts are copied
//! out of it (`docker create` + `docker cp`), see [`ExportMethod`]. The MRENCLAVE inside it is computed by `sgx_sign` from the
//! enclave image the client just built from source, so it does not depend
//! on anything the remote operator says. Because the build
//! (`containers/Dockerfile.nix-build`) is bit-for-bit reproducible, an
//! honest operator running the same source gets the same MRENCLAVE.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use sgx_ra_core::Measurement;

use crate::error::ClientError;
use crate::measurement::{GendataFile, MeasurementSource};

/// File name of the `sgx_sign gendata` output.
pub const GENDATA_FILE: &str = "enclave.so.gendata";
/// File name of the MRENCLAVE the build publishes (hex), if any.
pub const MRENCLAVE_FILE: &str = "MRENCLAVE.txt";
/// File name of the MRSIGNER the build publishes (hex), if any.
pub const MRSIGNER_FILE: &str = "MRSIGNER.txt";
/// How deep below the output directory to look for [`GENDATA_FILE`]
/// (`containers/Dockerfile.nix-build` exports it as `out/enclave.so.gendata`).
const SEARCH_DEPTH: usize = 3;

/// The container engine that runs the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerEngine {
    /// Docker with BuildKit (needed for `--output`).
    Docker,
    /// Podman (≥ 4 supports `--output`).
    Podman,
}

impl ContainerEngine {
    /// The executable name.
    pub fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    /// The first engine found on `PATH`, preferring Docker.
    pub fn detect() -> Option<Self> {
        [Self::Docker, Self::Podman]
            .into_iter()
            .find(|e| find_in_path(e.program()).is_some())
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Build failures.
#[derive(Debug)]
pub enum BuildError {
    /// Neither docker nor podman is installed.
    NoEngine,
    /// The output directory exists and is not empty, or cannot be created.
    OutputDir {
        /// The directory.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// The engine could not be started.
    Spawn {
        /// The program.
        program: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The build failed.
    Failed {
        /// The command line.
        command: String,
        /// Its exit status.
        status: ExitStatus,
    },
    /// The build output contains no [`GENDATA_FILE`].
    NoGendata(PathBuf),
    /// The build output contains several [`GENDATA_FILE`]s.
    AmbiguousGendata(Vec<PathBuf>),
    /// Reading or parsing a build artefact failed.
    Artifact(ClientError),
    /// The build's published MRENCLAVE disagrees with its own gendata.
    InconsistentMeasurement {
        /// MRENCLAVE in the gendata.
        gendata: Measurement,
        /// MRENCLAVE in [`MRENCLAVE_FILE`].
        published: Measurement,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEngine => f.write_str("neither docker nor podman was found on PATH"),
            Self::OutputDir { path, reason } => {
                write!(f, "build output directory {}: {reason}", path.display())
            }
            Self::Spawn { program, source } => write!(f, "cannot run {program}: {source}"),
            Self::Failed { command, status } => write!(f, "`{command}` failed ({status})"),
            Self::NoGendata(dir) => write!(
                f,
                "the build exported no {GENDATA_FILE} under {}",
                dir.display()
            ),
            Self::AmbiguousGendata(paths) => {
                write!(
                    f,
                    "the build exported several {GENDATA_FILE} files: {paths:?}"
                )
            }
            Self::Artifact(e) => write!(f, "invalid build artefact: {e}"),
            Self::InconsistentMeasurement { gendata, published } => write!(
                f,
                "build output is inconsistent: {GENDATA_FILE} has MRENCLAVE {gendata}, \
                 {MRENCLAVE_FILE} says {published}"
            ),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::Artifact(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ClientError> for BuildError {
    fn from(e: ClientError) -> Self {
        Self::Artifact(e)
    }
}

/// How the build's artefacts get out of the container engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportMethod {
    /// `--output type=local` when the engine supports it (podman, docker
    /// with buildx), else [`ExportMethod::CopyFromImage`] from `/out`.
    Auto,
    /// `build --output type=local,dest=<dir>`: the final stage's whole
    /// filesystem is written to the output directory.
    LocalOutput,
    /// Classic builder: `build -t <tag>`, then `create` + `cp
    /// <container>:<path> <dir>/<basename of path>` + `rm`. The image tag is
    /// kept so the layer cache survives for the next run.
    CopyFromImage {
        /// Directory inside the final image holding the artefacts.
        path: String,
        /// Image tag to build.
        tag: String,
    },
}

/// Default artefact directory of `containers/Dockerfile.nix-build`.
pub const DEFAULT_IMAGE_EXPORT_PATH: &str = "/out";
/// Default tag for [`ExportMethod::CopyFromImage`].
pub const DEFAULT_IMAGE_TAG: &str = "sgx-ra-client-build:latest";

impl ExportMethod {
    /// Copy `/out` out of an image tagged [`DEFAULT_IMAGE_TAG`].
    pub fn copy_from_image() -> Self {
        Self::CopyFromImage {
            path: DEFAULT_IMAGE_EXPORT_PATH.into(),
            tag: DEFAULT_IMAGE_TAG.into(),
        }
    }
}

/// A container build that exports the enclave artefacts.
#[derive(Debug, Clone)]
pub struct ReproducibleBuild {
    engine: ContainerEngine,
    dockerfile: PathBuf,
    context: PathBuf,
    build_args: Vec<(String, String)>,
    no_cache: bool,
    export: ExportMethod,
}

impl ReproducibleBuild {
    /// A build of `dockerfile` with build context `context`.
    pub fn new(
        engine: ContainerEngine,
        dockerfile: impl Into<PathBuf>,
        context: impl Into<PathBuf>,
    ) -> Self {
        Self {
            engine,
            dockerfile: dockerfile.into(),
            context: context.into(),
            build_args: Vec::new(),
            no_cache: false,
            export: ExportMethod::Auto,
        }
    }

    /// Adds `--build-arg key=value`.
    #[must_use]
    pub fn build_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.build_args.push((key.into(), value.into()));
        self
    }

    /// Passes `--no-cache` (rebuild every layer).
    #[must_use]
    pub fn no_cache(mut self, no_cache: bool) -> Self {
        self.no_cache = no_cache;
        self
    }

    /// Selects the export method.
    #[must_use]
    pub fn export(mut self, export: ExportMethod) -> Self {
        self.export = export;
        self
    }

    /// Resolves [`ExportMethod::Auto`] for this engine.
    pub fn resolved_export(&self) -> ExportMethod {
        match (&self.export, self.engine) {
            (ExportMethod::Auto, ContainerEngine::Podman) => ExportMethod::LocalOutput,
            (ExportMethod::Auto, ContainerEngine::Docker) => {
                // `--output` needs BuildKit through the buildx plugin;
                // without it Docker ≥ 23 refuses to build at all unless
                // the classic builder is selected.
                let buildx = Command::new("docker")
                    .args(["buildx", "version"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if buildx {
                    ExportMethod::LocalOutput
                } else {
                    log::info!("docker buildx is not available: using the classic builder");
                    ExportMethod::copy_from_image()
                }
            }
            (explicit, _) => explicit.clone(),
        }
    }

    /// The `build` command for `export` (not [`ExportMethod::Auto`]).
    pub fn build_command(&self, export: &ExportMethod, output_dir: &Path) -> Command {
        let mut cmd = Command::new(self.engine.program());
        cmd.arg("build").arg("-f").arg(&self.dockerfile);
        match export {
            ExportMethod::CopyFromImage { tag, .. } => {
                cmd.arg("-t").arg(tag);
                if self.engine == ContainerEngine::Docker {
                    cmd.env("DOCKER_BUILDKIT", "0");
                }
            }
            ExportMethod::LocalOutput | ExportMethod::Auto => {
                let mut output = OsString::from("type=local,dest=");
                output.push(output_dir);
                cmd.arg("--output").arg(output);
                if self.engine == ContainerEngine::Docker {
                    cmd.env("DOCKER_BUILDKIT", "1");
                }
            }
        }
        for (key, value) in &self.build_args {
            cmd.arg("--build-arg").arg(format!("{key}={value}"));
        }
        if self.no_cache {
            cmd.arg("--no-cache");
        }
        cmd.arg(&self.context);
        cmd
    }

    /// Runs the build, exporting into `output_dir` (created if missing;
    /// must be empty so stale artefacts cannot be picked up). The engine's
    /// own output goes to this process's stderr.
    pub fn run(&self, output_dir: &Path) -> Result<BuildOutput, BuildError> {
        prepare_output_dir(output_dir)?;
        let export = self.resolved_export();
        self.exec(self.build_command(&export, output_dir))?;
        if let ExportMethod::CopyFromImage { path, tag } = &export {
            self.copy_out(tag, path, output_dir)?;
        }
        BuildOutput::from_dir(output_dir)
    }

    /// `create` a (never started) container from `tag`, copy `path` out,
    /// remove the container.
    fn copy_out(&self, tag: &str, path: &str, output_dir: &Path) -> Result<(), BuildError> {
        let program = self.engine.program();
        let mut create = Command::new(program);
        // Images built `FROM scratch` have no default command.
        create.args(["create", tag, "/nonexistent"]);
        let created = create
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|source| BuildError::Spawn { program, source })?;
        if !created.status.success() {
            return Err(BuildError::Failed {
                command: format!("{create:?}"),
                status: created.status,
            });
        }
        let container = String::from_utf8_lossy(&created.stdout).trim().to_owned();
        let name = Path::new(path)
            .file_name()
            .map_or_else(|| OsString::from("export"), ToOwned::to_owned);
        let mut cp = Command::new(program);
        cp.arg("cp")
            .arg(format!("{container}:{path}"))
            .arg(output_dir.join(name));
        let copied = self.exec(cp);
        let mut rm = Command::new(program);
        rm.args(["rm", &container]);
        if let Err(e) = self.exec(rm) {
            log::warn!("cannot remove build container {container}: {e}");
        }
        copied
    }

    fn exec(&self, mut cmd: Command) -> Result<(), BuildError> {
        let command_line = format!("{cmd:?}");
        log::info!("running {command_line}");
        // Engine logs belong on stderr; stdout is the client's report.
        let stdout_to_stderr = io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .map_or_else(|_| Stdio::null(), Stdio::from);
        let status = cmd
            .stdin(Stdio::null())
            .stdout(stdout_to_stderr)
            .stderr(Stdio::inherit())
            .status()
            .map_err(|source| BuildError::Spawn {
                program: self.engine.program(),
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(BuildError::Failed {
                command: command_line,
                status,
            })
        }
    }
}

fn prepare_output_dir(dir: &Path) -> Result<(), BuildError> {
    let err = |reason: String| BuildError::OutputDir {
        path: dir.to_owned(),
        reason,
    };
    match fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(err("exists and is not empty".into()));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| err(e.to_string()))
        }
        Err(e) => Err(err(e.to_string())),
    }
}

/// The exported artefacts of a build.
#[derive(Debug, Clone)]
pub struct BuildOutput {
    gendata: GendataFile,
    mr_enclave: Measurement,
    published_mr_signer: Option<Measurement>,
}

impl BuildOutput {
    /// Locates and checks the artefacts in an export directory: exactly
    /// one [`GENDATA_FILE`]; if an [`MRENCLAVE_FILE`] sits next to it, it
    /// must agree with the gendata.
    pub fn from_dir(dir: &Path) -> Result<Self, BuildError> {
        let mut found = Vec::new();
        find_files(dir, GENDATA_FILE, SEARCH_DEPTH, &mut found).map_err(|source| {
            BuildError::Artifact(ClientError::ReadFile {
                path: dir.to_owned(),
                source,
            })
        })?;
        let gendata_path = match found.len() {
            0 => return Err(BuildError::NoGendata(dir.to_owned())),
            1 => found.remove(0),
            _ => return Err(BuildError::AmbiguousGendata(found)),
        };
        let gendata = GendataFile::new(&gendata_path);
        let mr_enclave = gendata.mr_enclave()?;
        let artefact_dir = gendata_path.parent().unwrap_or(dir);
        if let Some(published) = read_measurement(&artefact_dir.join(MRENCLAVE_FILE))?
            && published != mr_enclave
        {
            return Err(BuildError::InconsistentMeasurement {
                gendata: mr_enclave,
                published,
            });
        }
        let published_mr_signer = read_measurement(&artefact_dir.join(MRSIGNER_FILE))?;
        Ok(Self {
            gendata,
            mr_enclave,
            published_mr_signer,
        })
    }

    /// The gendata file.
    pub fn gendata(&self) -> &GendataFile {
        &self.gendata
    }

    /// MRENCLAVE of the locally built enclave.
    pub fn mr_enclave(&self) -> Measurement {
        self.mr_enclave
    }

    /// MRSIGNER the build published for its signing key, if any. This is
    /// informational: the gendata does not contain the signer.
    pub fn published_mr_signer(&self) -> Option<Measurement> {
        self.published_mr_signer
    }
}

impl MeasurementSource for BuildOutput {
    fn mr_enclave(&self) -> Result<Measurement, ClientError> {
        Ok(self.mr_enclave)
    }
}

fn read_measurement(path: &Path) -> Result<Option<Measurement>, ClientError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(Measurement::from_hex(text.trim())?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ClientError::ReadFile {
            path: path.to_owned(),
            source,
        }),
    }
}

fn find_files(dir: &Path, name: &str, depth: usize, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_file() && entry.file_name() == name {
            out.push(entry.path());
        } else if file_type.is_dir() && depth > 0 {
            find_files(&entry.path(), name, depth - 1, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLUEPRINT_MRENCLAVE: &str =
        "ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("sgx-ra-client-build-tests-{}", std::process::id()))
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn gendata_fixture() -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/blueprint_enclave.so.gendata"),
        )
        .unwrap()
    }

    #[test]
    fn command_line() {
        let build = ReproducibleBuild::new(
            ContainerEngine::Docker,
            "containers/Dockerfile.nix-build",
            ".",
        )
        .build_arg("ENCLAVE", "enclave")
        .no_cache(true);
        let cmd = build.build_command(&ExportMethod::LocalOutput, Path::new("/tmp/x"));
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(cmd.get_program(), "docker");
        assert_eq!(
            args,
            [
                "build",
                "-f",
                "containers/Dockerfile.nix-build",
                "--output",
                "type=local,dest=/tmp/x",
                "--build-arg",
                "ENCLAVE=enclave",
                "--no-cache",
                "."
            ]
        );
    }

    #[test]
    fn classic_command_line() {
        let build = ReproducibleBuild::new(ContainerEngine::Docker, "D", "ctx");
        let cmd = build.build_command(&ExportMethod::copy_from_image(), Path::new("/tmp/x"));
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["build", "-f", "D", "-t", DEFAULT_IMAGE_TAG, "ctx"]);
        assert!(
            cmd.get_envs()
                .any(|(k, v)| k == "DOCKER_BUILDKIT" && v == Some("0".as_ref()))
        );
        let podman = ReproducibleBuild::new(ContainerEngine::Podman, "D", "ctx");
        assert_eq!(podman.resolved_export(), ExportMethod::LocalOutput);
    }

    #[test]
    fn finds_nested_gendata_and_cross_checks() {
        let dir = scratch("nested");
        fs::create_dir_all(dir.join("out")).unwrap();
        fs::write(dir.join("out").join(GENDATA_FILE), gendata_fixture()).unwrap();
        fs::write(
            dir.join("out").join(MRENCLAVE_FILE),
            format!("{BLUEPRINT_MRENCLAVE}\n"),
        )
        .unwrap();
        let out = BuildOutput::from_dir(&dir).unwrap();
        assert_eq!(out.mr_enclave().to_string(), BLUEPRINT_MRENCLAVE);
        assert_eq!(out.published_mr_signer(), None);

        fs::write(dir.join("out").join(MRENCLAVE_FILE), "00".repeat(32)).unwrap();
        assert!(matches!(
            BuildOutput::from_dir(&dir),
            Err(BuildError::InconsistentMeasurement { .. })
        ));
    }

    #[test]
    fn missing_or_ambiguous_gendata() {
        let dir = scratch("missing");
        assert!(matches!(
            BuildOutput::from_dir(&dir),
            Err(BuildError::NoGendata(_))
        ));
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        fs::write(dir.join("a").join(GENDATA_FILE), gendata_fixture()).unwrap();
        fs::write(dir.join("b").join(GENDATA_FILE), gendata_fixture()).unwrap();
        assert!(matches!(
            BuildOutput::from_dir(&dir),
            Err(BuildError::AmbiguousGendata(p)) if p.len() == 2
        ));
    }

    #[test]
    fn output_dir_must_be_empty() {
        let dir = scratch("nonempty");
        fs::write(dir.join("stale"), b"x").unwrap();
        assert!(matches!(
            prepare_output_dir(&dir),
            Err(BuildError::OutputDir { .. })
        ));
        assert!(prepare_output_dir(&dir.join("fresh")).is_ok());
    }
}
