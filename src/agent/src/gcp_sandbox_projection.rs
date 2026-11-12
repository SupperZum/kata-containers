// SPDX-License-Identifier: Apache-2.0

//! Maps remote Kata requests for the fixed GCP workload to the protected task
//! RPC. The signed candidate supplies all applied settings. The gateway checks
//! and discards CRI plumbing such as copy paths, mounts, and annotations.

use anyhow::{bail, ensure, Context, Result};
use image_rs::preparation::launch_spec::BoundEffectiveSpec;
use protocols::{
    agent::{CreateContainerRequest, Storage},
    oci::{LinuxCPU, LinuxHugepageLimit, LinuxMemory, LinuxNamespace, LinuxResources, Mount, Spec},
};
use std::{collections::BTreeMap, net::Ipv4Addr};

const CRI_ROLE: &str = "io.kubernetes.cri.container-type";
const CRI_IMAGE: &str = "io.kubernetes.cri.image-name";
const KATA_ROLE: &str = "io.katacontainers.pkg.oci.container_type";
const CRI_WIRE_VERSION: &str = "1.3.0";
const CRI_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TERMINATION_PATH: &str = "/dev/termination-log";
const CRI_DEFAULT_APPARMOR: &str = "cri-containerd.apparmor.d";
const TERMINATION_PATH_ANNOTATION: &str = "io.kubernetes.container.terminationMessagePath";
const TERMINATION_POLICY_ANNOTATION: &str = "io.kubernetes.container.terminationMessagePolicy";
const PULL_DRIVER: &str = "image_guest_pull";
const MAX_IMAGE_REF_BYTES: usize = 512;

/// The owner authenticates the CID, image reference and protected spec. The
/// sandbox ID and copy paths are observed transport selectors.
pub(crate) fn project_app_create(
    request: &CreateContainerRequest,
    container_id: &str,
    image_ref: &str,
    candidate: &BoundEffectiveSpec,
    sandbox_id: &str,
    accepted_copies: &[String],
) -> Result<CreateContainerRequest> {
    ensure!(
        !matches!(container_id, "" | "." | "..")
            && container_id.len() <= execution_proof_contract::MAX_ID_BYTES
            && container_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            && request.container_id == container_id
            && request.exec_id == container_id,
        "GCP sandbox application selector rejected"
    );
    ensure!(
        valid_image_ref(image_ref),
        "GCP sandbox image reference rejected"
    );
    ensure!(
        candidate.args() == ["/app"]
            && candidate.cwd() == "/"
            && candidate.uid() == 1000
            && candidate.gid() == 1000,
        "GCP sandbox application profile rejected"
    );
    let submitted = request
        .OCI
        .as_ref()
        .context("GCP sandbox application spec missing")?;
    let cri_wire = submitted.Version == CRI_WIRE_VERSION;
    if cri_wire {
        let [path, hostname, home] = candidate.env() else {
            bail!("GCP sandbox CRI environment rejected");
        };
        ensure!(
            path == CRI_PATH
                && home == "HOME=/"
                && hostname
                    .strip_prefix("HOSTNAME=")
                    .is_some_and(|name| name == "(none)" || dns_label(name)),
            "GCP sandbox CRI environment rejected"
        );
    } else {
        ensure!(
            candidate.env() == ["HOME=/"] && accepted_copies.is_empty(),
            "GCP sandbox minimal wire profile rejected"
        );
    }
    let signed: oci_spec::runtime::Spec = serde_json::from_slice(candidate.raw_bytes())
        .context("GCP sandbox signed spec rejected")?;
    let protected: Spec = signed.into();
    let mut expected = protected.clone();
    let root_path = format!("/run/kata-containers/{container_id}/rootfs");
    expected
        .Root
        .as_mut()
        .context("GCP sandbox signed root missing")?
        .Path = root_path.clone();
    expected
        .Annotations
        .insert(CRI_ROLE.into(), "container".into());
    // The remote host may omit the version field and empty capability message.
    // When present they must equal the protected candidate or the pinned CRI
    // version handled below.
    if submitted.Version.is_empty() {
        expected.Version.clear();
    }
    let submitted_process = submitted
        .Process
        .as_ref()
        .context("GCP sandbox process missing")?;
    let expected_process = expected
        .Process
        .as_mut()
        .context("GCP sandbox signed process missing")?;
    if submitted_process.Capabilities.is_none() {
        expected_process.Capabilities = None.into();
    }
    let submitted_linux = submitted
        .Linux
        .as_ref()
        .context("GCP sandbox Linux spec missing")?;
    let expected_linux = expected
        .Linux
        .as_mut()
        .context("GCP sandbox signed Linux spec missing")?;
    // Kata Go omits PID and network and uses the OCI spelling "mount". The
    // Rust OCI conversion uses "mnt"/"net" in the protected RPC.
    expected_linux
        .Namespaces
        .retain(|ns| ns.Type != "pid" && ns.Type != "net");
    for namespace in &mut expected_linux.Namespaces {
        if namespace.Type == "mnt" {
            namespace.Type = "mount".into();
        }
    }
    expected_linux.Resources = Some(LinuxResources::new()).into();
    if submitted_linux.Seccomp.is_none() {
        expected_linux.Seccomp = None.into();
    }

    let metadata = if cri_wire {
        project_cri_defaults(
            &mut expected,
            submitted,
            container_id,
            sandbox_id,
            image_ref,
            accepted_copies,
        )?;
        expected
            .Annotations
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    } else {
        BTreeMap::from([(KATA_ROLE, "pod_container"), (CRI_IMAGE, image_ref)])
    };
    // Kata Go's encoding/json sorts these keys. Reconstruct the bounded
    // descriptor and compare it without accepting arbitrary driver options.
    let metadata = serde_json::to_string(&metadata)?;
    let driver_option = format!("image_guest_pull={{\"metadata\":{metadata}}}");
    let wire = CreateContainerRequest {
        container_id: container_id.into(),
        exec_id: container_id.into(),
        storages: vec![Storage {
            driver: PULL_DRIVER.into(),
            driver_options: vec![driver_option],
            source: image_ref.into(),
            fstype: "overlay".into(),
            mount_point: root_path,
            ..Default::default()
        }],
        OCI: Some(expected).into(),
        ..Default::default()
    };
    // Generated equality also checks nested field presence and unknown fields.
    ensure!(
        request == &wire,
        "GCP sandbox application wire profile rejected"
    );

    Ok(CreateContainerRequest {
        container_id: container_id.into(),
        exec_id: container_id.into(),
        OCI: Some(protected).into(),
        ..Default::default()
    })
}

fn project_cri_defaults(
    expected: &mut Spec,
    submitted: &Spec,
    container_id: &str,
    sandbox_id: &str,
    image_ref: &str,
    accepted_copies: &[String],
) -> Result<()> {
    ensure!(
        lower_hex(container_id, 64)
            && lower_hex(sandbox_id, 64)
            && container_id != sandbox_id
            && matches!(accepted_copies.len(), 3 | 4),
        "GCP sandbox CRI selectors rejected"
    );
    let kubelet_wire = accepted_copies.len() == 4;
    let annotation = |key: &str| submitted.Annotations.get(key).map_or("", String::as_str);
    let bundle = annotation("io.katacontainers.pkg.oci.bundle_path");
    let sandbox_name = annotation("io.kubernetes.cri.sandbox-name");
    let namespace = annotation("io.kubernetes.cri.sandbox-namespace");
    let pod_uid = annotation("io.kubernetes.cri.sandbox-uid");
    let bundle_suffix = format!("/io.containerd.runtime.v2.task/k8s.io/{container_id}");
    ensure!(
        matches!(
            bundle.strip_suffix(&bundle_suffix),
            Some("/run/containerd" | "/run/probe/state")
        ) && dns_label(sandbox_name)
            && dns_label(namespace)
            && pod_uid.len() == 36
            && pod_uid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    is_lower_hex(b)
                }
            }),
        "GCP sandbox CRI metadata rejected"
    );
    expected.Annotations = [
        (CRI_ROLE, "container"),
        (CRI_IMAGE, image_ref),
        (KATA_ROLE, "pod_container"),
        ("io.katacontainers.pkg.oci.bundle_path", bundle),
        ("io.kubernetes.cri.container-name", "workload"),
        ("io.kubernetes.cri.sandbox-id", sandbox_id),
        ("io.kubernetes.cri.sandbox-name", sandbox_name),
        ("io.kubernetes.cri.sandbox-namespace", namespace),
        ("io.kubernetes.cri.sandbox-uid", pod_uid),
    ]
    .iter()
    .copied()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    if kubelet_wire {
        expected
            .Annotations
            .insert(TERMINATION_PATH_ANNOTATION.into(), TERMINATION_PATH.into());
        expected
            .Annotations
            .insert(TERMINATION_POLICY_ANNOTATION.into(), "File".into());
    }
    expected.Version = CRI_WIRE_VERSION.into();

    let process = expected
        .Process
        .as_mut()
        .context("GCP sandbox signed process missing")?;
    let user = process
        .User
        .as_mut()
        .context("GCP sandbox signed user missing")?;
    // CRI includes the primary GID again as the sole supplementary GID.
    // It adds no group access. The protected process uses its signed GID.
    user.AdditionalGids = vec![user.GID];
    let linux = expected
        .Linux
        .as_mut()
        .context("GCP sandbox signed Linux spec missing")?;
    linux.CgroupsPath = format!("/k8s.io/{container_id}");
    linux.Namespaces = ["ipc", "uts", "mount"]
        .map(|kind| LinuxNamespace {
            Type: kind.into(),
            ..Default::default()
        })
        .into();
    if kubelet_wire {
        let submitted_process = submitted.Process.as_ref().context("CRI process missing")?;
        let service_env = submitted_process
            .Env
            .strip_prefix(process.Env.as_slice())
            .context("GCP sandbox kubelet environment rejected")?;
        validate_service_environment(service_env)?;
        process.Env.extend_from_slice(service_env);
        // Containerd may attach its host runtime default. It is only checked
        // on the incoming wire. The protected RPC keeps the signed process.
        if submitted_process.ApparmorProfile == CRI_DEFAULT_APPARMOR {
            process.ApparmorProfile = CRI_DEFAULT_APPARMOR.into();
        }
        process.OOMScoreAdj = 1000;
        let submitted_linux = submitted.Linux.as_ref().context("CRI Linux spec missing")?;
        linux.CgroupsPath = format!(
            "kubepods-besteffort-pod{}.slice:cri-containerd:{container_id}",
            pod_uid.replace('-', "_")
        );
        let resources = submitted_linux
            .Resources
            .as_ref()
            .context("GCP sandbox kubelet resources missing")?;
        linux.Resources = Some(besteffort_resources(resources)?).into();
        linux.MaskedPaths = [
            "/proc/asound",
            "/proc/acpi",
            "/proc/interrupts",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/sys/firmware",
            "/sys/devices/virtual/powercap",
        ]
        .map(String::from)
        .into();
        // Kubelet can append thermal masks for the four supported vCPUs.
        for cpu in 0..4 {
            let path = format!("/sys/devices/system/cpu/cpu{cpu}/thermal_throttle");
            if submitted_linux.MaskedPaths.contains(&path) {
                linux.MaskedPaths.push(path);
            }
        }
        linux.ReadonlyPaths = [
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger",
        ]
        .map(String::from)
        .into();
    }
    expected.Mounts = cri_default_mounts(container_id, accepted_copies, kubelet_wire)?;
    Ok(())
}

// The service IPv4 address changes with the cluster. Only the exact kubelet
// transport variables for that one address are accepted, in any order.
fn validate_service_environment(env: &[String]) -> Result<()> {
    ensure!(
        env.len() == 8,
        "GCP sandbox Kubernetes service environment rejected"
    );
    let host = env
        .iter()
        .find_map(|entry| entry.strip_prefix("KUBERNETES_SERVICE_HOST="))
        .context("GCP sandbox Kubernetes service host missing")?;
    let address: Ipv4Addr = host
        .parse()
        .context("GCP sandbox Kubernetes service IPv4 rejected")?;
    let mut expected = [
        format!("KUBERNETES_SERVICE_HOST={address}"),
        "KUBERNETES_SERVICE_PORT=443".into(),
        "KUBERNETES_SERVICE_PORT_HTTPS=443".into(),
        format!("KUBERNETES_PORT=tcp://{address}:443"),
        format!("KUBERNETES_PORT_443_TCP=tcp://{address}:443"),
        "KUBERNETES_PORT_443_TCP_PROTO=tcp".into(),
        "KUBERNETES_PORT_443_TCP_PORT=443".into(),
        format!("KUBERNETES_PORT_443_TCP_ADDR={address}"),
    ];
    let mut submitted: Vec<&str> = env.iter().map(String::as_str).collect();
    expected.sort_unstable();
    submitted.sort_unstable();
    ensure!(
        submitted == expected.each_ref().map(String::as_str),
        "GCP sandbox Kubernetes service environment rejected"
    );
    Ok(())
}

fn besteffort_resources(submitted: &LinuxResources) -> Result<LinuxResources> {
    // Kubelet can attach a zero limit for each supported x86 hugepage size.
    let mut hugepage_limits = Vec::new();
    for limit in &submitted.HugepageLimits {
        ensure!(
            matches!(limit.Pagesize.as_str(), "2MB" | "1GB")
                && !hugepage_limits
                    .iter()
                    .any(|prior: &LinuxHugepageLimit| prior.Pagesize == limit.Pagesize),
            "GCP sandbox kubelet hugepage size rejected"
        );
        hugepage_limits.push(LinuxHugepageLimit {
            Pagesize: limit.Pagesize.clone(),
            ..Default::default()
        });
    }
    Ok(LinuxResources {
        Memory: Some(LinuxMemory::new()).into(),
        CPU: Some(LinuxCPU {
            Shares: 2,
            Period: 100_000,
            ..Default::default()
        })
        .into(),
        HugepageLimits: hugepage_limits,
        ..Default::default()
    })
}

fn cri_default_mounts(
    container_id: &str,
    accepted_copies: &[String],
    kubelet_wire: bool,
) -> Result<Vec<Mount>> {
    let mount = |destination: &str, source: &str, kind: &str, options: &[&str]| Mount {
        destination: destination.into(),
        source: source.into(),
        type_: kind.into(),
        options: options.iter().map(|value| (*value).into()).collect(),
        ..Default::default()
    };
    let no_exec = &["nosuid", "noexec", "nodev"];
    let mut mounts = vec![
        mount("/proc", "proc", "proc", no_exec),
        mount(
            "/dev",
            "tmpfs",
            "tmpfs",
            &["nosuid", "strictatime", "mode=755", "size=65536k"],
        ),
        mount(
            "/dev/pts",
            "devpts",
            "devpts",
            &[
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
                "gid=5",
            ],
        ),
        mount("/dev/mqueue", "mqueue", "mqueue", no_exec),
        mount(
            "/sys",
            "sysfs",
            "sysfs",
            &["nosuid", "noexec", "nodev", "ro"],
        ),
        mount(
            "/sys/fs/cgroup",
            "cgroup",
            "cgroup",
            &["nosuid", "noexec", "nodev", "relatime", "ro"],
        ),
    ];
    let prefix = format!("/run/kata-containers/shared/containers/{container_id}-");
    let copy_mounts: &[(&str, &str, &str)] = if kubelet_wire {
        &[
            ("hosts", "/etc/hosts", "rw"),
            ("termination-log", TERMINATION_PATH, "rw"),
            ("hostname", "/etc/hostname", "ro"),
            ("resolv.conf", "/etc/resolv.conf", "ro"),
        ]
    } else {
        &[
            ("hostname", "/etc/hostname", "ro"),
            ("hosts", "/etc/hosts", "ro"),
            ("resolv.conf", "/etc/resolv.conf", "ro"),
        ]
    };
    for &(name, destination, access) in copy_mounts {
        let suffix = format!("-{name}");
        let source = accepted_copies
            .iter()
            .find(|path| {
                path.strip_prefix(&prefix)
                    .and_then(|tail| tail.strip_suffix(&suffix))
                    .is_some_and(|nonce| lower_hex(nonce, 16))
            })
            .context("GCP sandbox CRI copy provenance missing")?;
        mounts.push(mount(
            destination,
            source,
            "bind",
            &["rbind", "rprivate", access],
        ));
    }
    mounts.push(mount(
        "/dev/shm",
        "/run/kata-containers/sandbox/shm",
        "bind",
        &["rbind"],
    ));
    Ok(mounts)
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(is_lower_hex)
}

fn valid_image_ref(image_ref: &str) -> bool {
    let Some((repository, digest)) = image_ref.split_once("@sha256:") else {
        return false;
    };
    image_ref.len() <= MAX_IMAGE_REF_BYTES
        && repository.contains('/')
        && repository
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/.:-_".contains(&b))
        && lower_hex(digest, 64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use image_rs::preparation::launch_spec::{EffectiveSpecLimits, EffectiveSpecPolicy};
    use protocols::oci::{
        Linux, LinuxCapabilities, LinuxNamespace, Mount, Process, Root, Spec, User,
    };
    use sha2::{Digest, Sha384};

    pub(crate) const CID: &str = "application-a";
    const ROOT: &str = "/run/kata-containers/application-a/rootfs";
    pub(crate) const IMAGE: &str = "registry.invalid/onb17/proof@sha256:27c0bda6a8b28891c8c45e0ddf9793f5bef4b2ce1aad6f6314447e346a243fc7";
    pub(crate) const CRI_CID: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const SANDBOX_ID: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SIGNED_SPEC: &[u8] = br#"{
        "ociVersion":"1.2.1",
        "root":{"path":"rootfs","readonly":true},
        "mounts":[],
        "process":{"terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},"args":["/app"],"env":["HOME=/"],"cwd":"/","capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]},"noNewPrivileges":true},
        "linux":{"namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}}
    }"#;

    pub(crate) fn candidate() -> BoundEffectiveSpec {
        bound(SIGNED_SPEC)
    }

    fn bound(spec: &[u8]) -> BoundEffectiveSpec {
        let digest = Sha384::digest(spec)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        BoundEffectiveSpec::parse(
            spec,
            &digest,
            &EffectiveSpecPolicy {
                uid: 1000,
                gid: 1000,
                seccomp_syscalls: ["execveat", "exit_group", "write"].map(String::from).into(),
            },
            EffectiveSpecLimits {
                spec_bytes: 4096,
                args: 4,
                env: 4,
                string_bytes: 128,
                total_string_bytes: 256,
                path_bytes: 64,
                path_components: 4,
                syscalls: 4,
                json_depth: 16,
            },
        )
        .unwrap()
    }

    pub(crate) fn cri_candidate() -> BoundEffectiveSpec {
        cri_candidate_with_hostname("(none)")
    }

    pub(crate) fn gke_candidate() -> BoundEffectiveSpec {
        cri_candidate_with_hostname("onb17-proof-1")
    }

    fn cri_candidate_with_hostname(hostname: &str) -> BoundEffectiveSpec {
        let mut signed: serde_json::Value = serde_json::from_slice(SIGNED_SPEC).unwrap();
        signed["process"]["env"] =
            serde_json::json!([CRI_PATH, format!("HOSTNAME={hostname}"), "HOME=/"]);
        bound(&serde_json::to_vec(&signed).unwrap())
    }

    // Shape observed at the ttrpc boundary of remote Kata with ForceGuestPull.
    pub(crate) fn host_request() -> CreateContainerRequest {
        CreateContainerRequest {
            container_id: CID.into(),
            exec_id: CID.into(),
            storages: vec![Storage {
                driver: "image_guest_pull".into(),
                driver_options: vec![format!(
                    "image_guest_pull={{\"metadata\":{{\"io.katacontainers.pkg.oci.container_type\":\"pod_container\",\"io.kubernetes.cri.image-name\":\"{IMAGE}\"}}}}"
                )],
                source: IMAGE.into(),
                fstype: "overlay".into(),
                mount_point: ROOT.into(),
                ..Default::default()
            }],
            OCI: Some(Spec {
                Process: Some(Process {
                    User: Some(User { UID: 1000, GID: 1000, ..Default::default() }).into(),
                    Args: vec!["/app".into()],
                    Env: vec!["HOME=/".into()],
                    Cwd: "/".into(),
                    NoNewPrivileges: true,
                    ..Default::default()
                }).into(),
                Root: Some(Root { Path: ROOT.into(), Readonly: true, ..Default::default() }).into(),
                Annotations: [(CRI_ROLE.into(), "container".into())].into(),
                Linux: Some(Linux {
                    Resources: Some(LinuxResources::new()).into(),
                    Namespaces: ["mount", "ipc", "uts"].map(|kind| LinuxNamespace {
                        Type: kind.into(), ..Default::default()
                    }).into(),
                    ..Default::default()
                }).into(),
                ..Default::default()
            }).into(),
            ..Default::default()
        }
    }

    fn project_minimal(
        request: &CreateContainerRequest,
        cid: &str,
        image: &str,
        candidate: &BoundEffectiveSpec,
    ) -> Result<CreateContainerRequest> {
        project_app_create(request, cid, image, candidate, "sandbox-a", &[])
    }

    // Observed with containerd 2.4.2 and Kata remote ForceGuestPull in QEMU.
    // Dynamic IDs/nonce values and the digest-pinned test image are fixed here.
    pub(crate) fn cri_request() -> (CreateContainerRequest, Vec<String>) {
        let mut req = host_request();
        req.container_id = CRI_CID.into();
        req.exec_id = CRI_CID.into();
        let root = format!("/run/kata-containers/{CRI_CID}/rootfs");
        req.storages[0].mount_point.clone_from(&root);
        let spec = req.OCI.as_mut().unwrap();
        spec.Version = "1.3.0".into();
        spec.Root.as_mut().unwrap().Path = root;
        let proc = spec.Process.as_mut().unwrap();
        proc.Capabilities = Some(LinuxCapabilities::new()).into();
        proc.User.as_mut().unwrap().AdditionalGids = vec![1000];
        proc.Env = [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOSTNAME=(none)",
            "HOME=/",
        ]
        .map(String::from)
        .into();
        let linux = spec.Linux.as_mut().unwrap();
        linux.CgroupsPath = format!("/k8s.io/{CRI_CID}");
        linux.Namespaces.rotate_left(1);
        let bundle = format!("/run/probe/state/io.containerd.runtime.v2.task/k8s.io/{CRI_CID}");
        let annotations = BTreeMap::from([
            ("io.katacontainers.pkg.oci.bundle_path", bundle.as_str()),
            ("io.katacontainers.pkg.oci.container_type", "pod_container"),
            ("io.kubernetes.cri.container-name", "workload"),
            ("io.kubernetes.cri.container-type", "container"),
            ("io.kubernetes.cri.image-name", IMAGE),
            ("io.kubernetes.cri.sandbox-id", SANDBOX_ID),
            ("io.kubernetes.cri.sandbox-name", "onb17-cri-probe"),
            ("io.kubernetes.cri.sandbox-namespace", "onb17-local"),
            (
                "io.kubernetes.cri.sandbox-uid",
                "6c2a0e29-7286-45f0-9f99-c7c36bf74ac3",
            ),
        ]);
        spec.Annotations = annotations
            .iter()
            .map(|(&key, &value)| (key.into(), value.into()))
            .collect();
        req.storages[0].driver_options[0] = format!(
            "image_guest_pull={{\"metadata\":{}}}",
            serde_json::to_string(&annotations).unwrap()
        );
        let [hostname, hosts, resolv] = [
            ("a256e26fb961f22b", "hostname"),
            ("10def1a0b26a68fc", "hosts"),
            ("62ec8af26fb4331d", "resolv.conf"),
        ]
        .map(|(nonce, name)| {
            format!("/run/kata-containers/shared/containers/{CRI_CID}-{nonce}-{name}")
        });
        spec.Mounts = [
            ("/proc", "proc", "proc", "nosuid,noexec,nodev"),
            (
                "/dev",
                "tmpfs",
                "tmpfs",
                "nosuid,strictatime,mode=755,size=65536k",
            ),
            (
                "/dev/pts",
                "devpts",
                "devpts",
                "nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5",
            ),
            ("/dev/mqueue", "mqueue", "mqueue", "nosuid,noexec,nodev"),
            ("/sys", "sysfs", "sysfs", "nosuid,noexec,nodev,ro"),
            (
                "/sys/fs/cgroup",
                "cgroup",
                "cgroup",
                "nosuid,noexec,nodev,relatime,ro",
            ),
            ("/etc/hostname", &hostname, "bind", "rbind,rprivate,ro"),
            ("/etc/hosts", &hosts, "bind", "rbind,rprivate,ro"),
            ("/etc/resolv.conf", &resolv, "bind", "rbind,rprivate,ro"),
            (
                "/dev/shm",
                "/run/kata-containers/sandbox/shm",
                "bind",
                "rbind",
            ),
        ]
        .iter()
        .copied()
        .map(|(destination, source, kind, options)| Mount {
            destination: destination.into(),
            source: source.into(),
            type_: kind.into(),
            options: options.split(',').map(String::from).collect(),
            ..Default::default()
        })
        .collect();
        (req, vec![hostname, hosts, resolv])
    }

    #[test]
    fn containerd_wire_requires_signed_environment_and_exact_copy_mounts() {
        let (wire, copies) = cri_request();
        let approved = cri_candidate();
        let project = |request: &CreateContainerRequest, copies: &[String]| {
            project_app_create(request, CRI_CID, IMAGE, &approved, SANDBOX_ID, copies)
        };
        let protected = project(&wire, &copies).unwrap();
        let oci = protected.OCI.as_ref().unwrap();
        assert!(oci.Mounts.is_empty());
        assert!(oci.Annotations.is_empty());
        assert!(protected.storages.is_empty());
        let proc = oci.Process.as_ref().unwrap();
        assert_eq!(proc.Env, [CRI_PATH, "HOSTNAME=(none)", "HOME=/"]);
        assert!(proc.User.as_ref().unwrap().AdditionalGids.is_empty());
        crate::final_task_runtime::verified_protocol_spec(&approved, oci).unwrap();

        assert!(
            project_app_create(&wire, CRI_CID, IMAGE, &candidate(), SANDBOX_ID, &copies).is_err()
        );
        assert!(project(&wire, &copies[..2]).is_err());
        assert!(project_app_create(&wire, CRI_CID, IMAGE, &approved, CRI_CID, &copies).is_err());
        for change in ["copy", "mount", "env", "gid", "cgroup", "annotation"] {
            let mut mutated = wire.clone();
            let spec = mutated.OCI.as_mut().unwrap();
            let process = spec.Process.as_mut().unwrap();
            match change {
                "copy" => spec.Mounts[6].source = copies[1].clone(),
                "mount" => spec.Mounts[3].options.push("rw".into()),
                "env" => process.Env[1] = "HOSTNAME=other".into(),
                "gid" => process.User.as_mut().unwrap().AdditionalGids.push(2000),
                "cgroup" => spec.Linux.as_mut().unwrap().CgroupsPath = "/different".into(),
                "annotation" => {
                    spec.Annotations.insert("foreign".into(), "data".into());
                }
                _ => unreachable!(),
            }
            assert!(project(&mutated, &copies).is_err(), "{}", change);
        }
    }

    pub(crate) fn gke_request() -> (CreateContainerRequest, Vec<String>) {
        let (mut wire, mut copies) = cri_request();
        let spec = wire.OCI.as_mut().unwrap();
        let process = spec.Process.as_mut().unwrap();
        process.Env[1] = "HOSTNAME=onb17-proof-1".into();
        process.ApparmorProfile = "cri-containerd.apparmor.d".into();
        process.Env.extend(
            [
                "KUBERNETES_SERVICE_PORT=443",
                "KUBERNETES_SERVICE_PORT_HTTPS=443",
                "KUBERNETES_PORT=tcp://34.118.224.1:443",
                "KUBERNETES_PORT_443_TCP=tcp://34.118.224.1:443",
                "KUBERNETES_PORT_443_TCP_PROTO=tcp",
                "KUBERNETES_PORT_443_TCP_PORT=443",
                "KUBERNETES_PORT_443_TCP_ADDR=34.118.224.1",
                "KUBERNETES_SERVICE_HOST=34.118.224.1",
            ]
            .map(String::from),
        );
        // Use kubelet/containerd BestEffort systemd defaults for the wire fixture.
        process.OOMScoreAdj = 1000;
        let linux = spec.Linux.as_mut().unwrap();
        linux.CgroupsPath =
            format!("kubepods-besteffort-pod6c2a0e29_7286_45f0_9f99_c7c36bf74ac3.slice:cri-containerd:{CRI_CID}");
        linux.Resources = Some(LinuxResources {
            CPU: Some(LinuxCPU {
                Shares: 2,
                Period: 100_000,
                ..Default::default()
            })
            .into(),
            Memory: Some(LinuxMemory::new()).into(),
            HugepageLimits: vec![LinuxHugepageLimit {
                Pagesize: "2MB".into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .into();
        linux.MaskedPaths = [
            "/proc/asound",
            "/proc/acpi",
            "/proc/interrupts",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/sys/firmware",
            "/sys/devices/virtual/powercap",
        ]
        .map(String::from)
        .into();
        linux.ReadonlyPaths = [
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger",
        ]
        .map(String::from)
        .into();
        spec.Mounts.swap(6, 7);
        spec.Mounts[6].options[2] = "rw".into();
        let termination = format!(
            "/run/kata-containers/shared/containers/{CRI_CID}-dd56a5dc3499ce6a-termination-log"
        );
        copies.push(termination.clone());
        spec.Mounts.insert(
            7,
            Mount {
                destination: "/dev/termination-log".into(),
                source: termination,
                type_: "bind".into(),
                options: ["rbind", "rprivate", "rw"].map(String::from).into(),
                ..Default::default()
            },
        );
        spec.Annotations.extend([
            (
                "io.kubernetes.container.terminationMessagePath".into(),
                "/dev/termination-log".into(),
            ),
            (
                "io.kubernetes.container.terminationMessagePolicy".into(),
                "File".into(),
            ),
        ]);
        let metadata = spec.Annotations.iter().collect::<BTreeMap<_, _>>();
        wire.storages[0].driver_options[0] = format!(
            "image_guest_pull={{\"metadata\":{}}}",
            serde_json::to_string(&metadata).unwrap()
        );
        (wire, copies)
    }

    #[test]
    fn gke_kubelet_wire_projects_to_the_signed_task() {
        let (wire, copies) = gke_request();
        let approved = gke_candidate();
        let project = |request: &CreateContainerRequest, copies: &[String]| {
            project_app_create(request, CRI_CID, IMAGE, &approved, SANDBOX_ID, copies)
        };
        let protected = project(&wire, &copies).unwrap();
        let oci = protected.OCI.as_ref().unwrap();
        assert!(protected.storages.is_empty());
        assert!(oci.Mounts.is_empty() && oci.Annotations.is_empty());
        assert_eq!(oci.Process.as_ref().unwrap().Env, approved.env());
        crate::final_task_runtime::verified_protocol_spec(&approved, oci).unwrap();
        assert!(project(&wire, &copies[..3]).is_err());

        let mut different_order = wire.clone();
        different_order
            .OCI
            .as_mut()
            .unwrap()
            .Process
            .as_mut()
            .unwrap()
            .Env[3..]
            .reverse();
        assert_eq!(project(&different_order, &copies).unwrap(), protected);
        let mut thermal = wire.clone();
        thermal
            .OCI
            .as_mut()
            .unwrap()
            .Linux
            .as_mut()
            .unwrap()
            .MaskedPaths
            .push("/sys/devices/system/cpu/cpu2/thermal_throttle".into());
        assert_eq!(project(&thermal, &copies).unwrap(), protected);
        let mut no_apparmor = wire.clone();
        no_apparmor
            .OCI
            .as_mut()
            .unwrap()
            .Process
            .as_mut()
            .unwrap()
            .ApparmorProfile
            .clear();
        assert_eq!(project(&no_apparmor, &copies).unwrap(), protected);
        for change in [
            "mount",
            "hostname",
            "apparmor",
            "mask",
            "service IP",
            "duplicate env",
            "cgroup",
            "resource",
            "annotation",
            "storage",
        ] {
            let mut changed = wire.clone();
            let spec = changed.OCI.as_mut().unwrap();
            let process = spec.Process.as_mut().unwrap();
            let linux = spec.Linux.as_mut().unwrap();
            match change {
                "mount" => spec.Mounts[7].source = copies[0].clone(),
                "hostname" => process.Env[1] = "HOSTNAME=onb17-proof-2".into(),
                "apparmor" => process.ApparmorProfile = "arbitrary".into(),
                "mask" => linux
                    .MaskedPaths
                    .push("/sys/devices/system/cpu/cpu99/thermal_throttle".into()),
                "service IP" => process.Env[6] = "KUBERNETES_PORT=tcp://34.118.224.2:443".into(),
                "duplicate env" => process.Env[4] = process.Env[3].clone(),
                "cgroup" => linux.CgroupsPath.push('a'),
                "resource" => linux.Resources.as_mut().unwrap().HugepageLimits[0].Limit = 1,
                "annotation" => {
                    spec.Annotations.insert(
                        TERMINATION_POLICY_ANNOTATION.into(),
                        "FallbackToLogsOnError".into(),
                    );
                }
                "storage" => changed.storages[0].driver_options[0].push(' '),
                _ => unreachable!(),
            }
            assert!(project(&changed, &copies).is_err(), "{}", change);
        }
    }

    #[test]
    fn stock_wire_yields_exact_protected_task() {
        let candidate = candidate();
        let projected = project_minimal(&host_request(), CID, IMAGE, &candidate).unwrap();
        assert_eq!(projected.container_id, CID);
        assert_eq!(projected.exec_id, CID);
        assert!(projected.storages.is_empty());
        let spec = projected.OCI.as_ref().unwrap();
        assert!(spec.Annotations.is_empty());
        assert_eq!(spec.Root.as_ref().unwrap().Path, "rootfs");
        let linux = spec.Linux.as_ref().unwrap();
        assert!(linux.Seccomp.is_some());
        assert!(linux.Namespaces.iter().any(|ns| ns.Type == "pid"));
        assert!(linux.Namespaces.iter().any(|ns| ns.Type == "net"));
        crate::final_task_runtime::verified_protocol_spec(&candidate, spec).unwrap();
    }

    #[test]
    fn known_optional_host_fields_must_match_protected_values() {
        let candidate = candidate();
        let mut request = host_request();
        let protected = project_minimal(&request, CID, IMAGE, &candidate).unwrap();
        let protected = protected.OCI.as_ref().unwrap();
        let spec = request.OCI.as_mut().unwrap();
        spec.Version.clone_from(&protected.Version);
        spec.Process.as_mut().unwrap().Capabilities =
            protected.Process.as_ref().unwrap().Capabilities.clone();
        spec.Linux.as_mut().unwrap().Seccomp = protected.Linux.as_ref().unwrap().Seccomp.clone();
        assert!(project_minimal(&request, CID, IMAGE, &candidate).is_ok());
        request
            .OCI
            .as_mut()
            .unwrap()
            .Linux
            .as_mut()
            .unwrap()
            .Seccomp
            .as_mut()
            .unwrap()
            .DefaultAction = "SCMP_ACT_ALLOW".into();
        assert!(project_minimal(&request, CID, IMAGE, &candidate).is_err());
    }

    #[test]
    fn rejects_foreign_selectors_and_additional_effects() {
        let candidate = candidate();
        let base = host_request();
        assert!(project_minimal(&base, "foreign-id", IMAGE, &candidate).is_err());
        let foreign = IMAGE.replace("registry.invalid", "other.invalid");
        assert!(project_minimal(&base, CID, &foreign, &candidate).is_err());
        for change in [
            "exec-id",
            "digest",
            "extra-storage",
            "pull-metadata",
            "root",
            "mount",
            "role",
            "privilege",
            "capability",
            "command",
            "env",
            "namespace",
            "unknown",
        ] {
            let mut request = base.clone();
            let spec = request.OCI.as_mut().unwrap();
            let process = spec.Process.as_mut().unwrap();
            match change {
                "exec-id" => request.exec_id = "foreign-id".into(),
                "digest" => request.storages[0].source = IMAGE.replace("27c0", "17c0"),
                "extra-storage" => request.storages.push(Storage::new()),
                "pull-metadata" => request.storages[0].driver_options[0] =
                    format!("image_guest_pull={{\"metadata\":{{\"credentials\":\"forbidden\",\"io.katacontainers.pkg.oci.container_type\":\"pod_container\",\"io.kubernetes.cri.image-name\":\"{IMAGE}\"}}}}"),
                "root" => spec.Root.as_mut().unwrap().Readonly = false,
                "mount" => spec.Mounts.push(Mount::new()),
                "role" => { spec.Annotations.insert(CRI_ROLE.into(), "sandbox".into()); }
                "privilege" => process.NoNewPrivileges = false,
                "capability" => process.Capabilities = Some(LinuxCapabilities {
                    Bounding: vec!["CAP_SYS_ADMIN".into()], ..Default::default()
                }).into(),
                "command" => process.Args.push("changed".into()),
                "env" => process.Env.push("PATH=/usr/bin".into()),
                "namespace" => spec.Linux.as_mut().unwrap().Namespaces[0].Path = "/proc/1/ns/mnt".into(),
                "unknown" => process.special_fields.mut_unknown_fields().add_varint(100, 1),
                _ => unreachable!(),
            }
            assert!(
                project_minimal(&request, CID, IMAGE, &candidate).is_err(),
                "{}",
                change
            );
        }
    }
}
