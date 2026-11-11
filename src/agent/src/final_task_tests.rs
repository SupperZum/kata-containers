use super::*;
use image_rs::preparation::launch_spec::{EffectiveSpecLimits, EffectiveSpecPolicy};

fn raw_candidate() -> Value {
    json!({
        "ociVersion":"1.2.1", "root":{"path":"rootfs","readonly":true},
        "process":{"terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},
            "args":["/app","argument"],"env":["HOME=/","COLOR=blue"],"cwd":"/","noNewPrivileges":true,
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}},
        "mounts":[],"linux":{"namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],
            "seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],
                "syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}}
    })
}
fn candidate(raw: &[u8]) -> BoundEffectiveSpec {
    BoundEffectiveSpec::parse(
        raw,
        &hex(&Sha384::digest(raw)),
        &EffectiveSpecPolicy {
            uid: 1000,
            gid: 1000,
            seccomp_syscalls: vec!["execveat".into(), "exit_group".into(), "write".into()],
        },
        EffectiveSpecLimits {
            spec_bytes: 16384,
            args: 16,
            env: 16,
            string_bytes: 1024,
            total_string_bytes: 4096,
            path_bytes: 256,
            path_components: 16,
            syscalls: 32,
            json_depth: 16,
        },
    )
    .unwrap()
}
fn record(candidate: &BoundEffectiveSpec) -> PreparationRecord {
    PreparationRecord {
        context_sha384: "11".repeat(48),
        offer_sha384: "22".repeat(48),
        provenance_sha384: "33".repeat(48),
        validated_receipt_sha384: "44".repeat(48),
        image_sha384: "55".repeat(48),
        candidate_spec_sha384: candidate.sha384().into(),
        executable_sha384: "66".repeat(48),
        startup_binding_sha384: "77".repeat(48),
        receiver_nonce: "88".repeat(32),
        mount_id: 42,
        inodes: 2,
    }
}
fn actual(value: &Value) -> (Spec, Process) {
    (
        serde_json::from_value(value.clone()).unwrap(),
        serde_json::from_value(value["process"].clone()).unwrap(),
    )
}

#[test]
fn final_semantic_projection_keeps_the_original_signed_byte_commitment() {
    let value = raw_candidate();
    let raw = serde_json::to_vec_pretty(&value).unwrap();
    let checked = candidate(&raw);
    let (spec, process) = actual(&value);
    let (first, names) = project_spec(&checked, &spec, &process, &record(&checked)).unwrap();
    assert_eq!(names, vec!["execveat", "exit_group", "write"]);
    assert_ne!(first, checked.sha384());
    assert_eq!(checked.raw_bytes(), raw);
    let mut reordered = value.clone();
    reordered["linux"]["namespaces"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["linux"]["seccomp"]["syscalls"] = json!([
        {"names":["write"],"action":"SCMP_ACT_ALLOW"},
        {"names":["exit_group","execveat"],"action":"SCMP_ACT_ALLOW"}
    ]);
    let (spec, process) = actual(&reordered);
    assert_eq!(
        project_spec(&checked, &spec, &process, &record(&checked))
            .unwrap()
            .0,
        first
    );
    let compact = candidate(&serde_json::to_vec(&value).unwrap());
    let (spec, process) = actual(&value);
    assert_ne!(
        project_spec(&compact, &spec, &process, &record(&compact))
            .unwrap()
            .0,
        first
    );
}

#[cfg(feature = "gcp-proof-startup")]
#[test]
fn gcp_actual_protocol_wire_uses_original_signed_oci_for_final_projection() {
    use protobuf::Message;
    let value = raw_candidate();
    let raw = serde_json::to_vec_pretty(&value).unwrap();
    let checked = candidate(&raw);
    let (trusted, process) = actual(&value);
    let expected_projection =
        project_spec(&checked, &trusted, &process, &record(&checked)).unwrap();
    let protocol: protocols::oci::Spec = trusted.into();
    let wire = protocol.write_to_bytes().unwrap();
    let decoded = protocols::oci::Spec::parse_from_bytes(&wire).unwrap();
    let original = crate::final_task_runtime::verified_protocol_spec(&checked, &decoded).unwrap();
    // These fields are lost or defaulted by the shared protocol-to-OCI path.
    // The GCP gate preserves the signed source even though protobuf cannot
    // distinguish its empty vector or represent its fixed defaultErrnoRet.
    assert!(original.mounts().as_ref().is_some_and(Vec::is_empty));
    assert_eq!(
        original.root().as_ref().unwrap().path().to_str(),
        Some("rootfs")
    );
    assert_eq!(
        original
            .linux()
            .as_ref()
            .unwrap()
            .seccomp()
            .as_ref()
            .unwrap()
            .default_errno_ret(),
        Some(1)
    );
    let actual_process = original.process().as_ref().unwrap();
    assert_eq!(
        project_spec(&checked, &original, actual_process, &record(&checked)).unwrap(),
        expected_projection
    );
    assert_eq!(checked.raw_bytes(), raw);
}

#[cfg(feature = "gcp-proof-startup")]
#[test]
fn gcp_protocol_gate_rejects_wire_changes_and_nested_unknowns_before_conversion() {
    use protobuf::Message;
    let value = raw_candidate();
    let raw = serde_json::to_vec(&value).unwrap();
    let checked = candidate(&raw);
    let trusted: Spec = serde_json::from_value(value).unwrap();
    let expected: protocols::oci::Spec = trusted.into();
    for case in [
        "root",
        "uid",
        "syscall",
        "env",
        "username",
        "unknown-top",
        "unknown-user",
        "unknown-syscall",
        "invalid-action",
        "invalid-namespace",
    ] {
        let mut changed = expected.clone();
        match case {
            "root" => changed.Root.as_mut().unwrap().Path = "/run/host-root".into(),
            "uid" => changed.Process.as_mut().unwrap().User.as_mut().unwrap().UID = 0,
            "syscall" => changed
                .Linux
                .as_mut()
                .unwrap()
                .Seccomp
                .as_mut()
                .unwrap()
                .Syscalls[0]
                .Names
                .push("read".into()),
            "env" => changed.Process.as_mut().unwrap().Env[0] = "HOME=/other".into(),
            "username" => {
                changed
                    .Process
                    .as_mut()
                    .unwrap()
                    .User
                    .as_mut()
                    .unwrap()
                    .Username = "root".into()
            }
            "unknown-top" => changed
                .special_fields
                .mut_unknown_fields()
                .add_varint(99, 1),
            "unknown-user" => changed
                .Process
                .as_mut()
                .unwrap()
                .User
                .as_mut()
                .unwrap()
                .special_fields
                .mut_unknown_fields()
                .add_varint(99, 1),
            "unknown-syscall" => changed
                .Linux
                .as_mut()
                .unwrap()
                .Seccomp
                .as_mut()
                .unwrap()
                .Syscalls[0]
                .special_fields
                .mut_unknown_fields()
                .add_varint(99, 1),
            "invalid-action" => {
                changed
                    .Linux
                    .as_mut()
                    .unwrap()
                    .Seccomp
                    .as_mut()
                    .unwrap()
                    .DefaultAction = "INVALID_ENUM".into()
            }
            "invalid-namespace" => {
                changed.Linux.as_mut().unwrap().Namespaces[0].Type = "INVALID_ENUM".into()
            }
            _ => unreachable!(),
        }
        let wire = changed.write_to_bytes().unwrap();
        let decoded = protocols::oci::Spec::parse_from_bytes(&wire).unwrap();
        assert!(
            crate::final_task_runtime::verified_protocol_spec(&checked, &decoded).is_err(),
            "{}",
            case
        );
    }
}

#[test]
fn final_process_is_checked_separately_from_the_spec_process() {
    let value = raw_candidate();
    let checked = candidate(&serde_json::to_vec(&value).unwrap());
    let (spec, mut process) = actual(&value);
    process.set_args(Some(vec!["/other".into()]));
    assert_eq!(
        project_spec(&checked, &spec, &process, &record(&checked)).err(),
        Some(FinalTaskError::SpecRejected)
    );
}

#[test]
fn final_inputs_reject_every_unmodeled_transform() {
    let value = raw_candidate();
    let checked = candidate(&serde_json::to_vec(&value).unwrap());
    for case in [
        "root",
        "writable",
        "mount",
        "hook",
        "annotation",
        "uid",
        "gid",
        "groups",
        "caps",
        "nnp",
        "tty",
        "argv",
        "env",
        "cwd",
        "namespace-path",
        "duplicate-pid",
        "seccomp-default",
        "seccomp-arch",
        "seccomp-extra",
        "seccomp-duplicate",
        "seccomp-args",
        "resources",
        "umask",
    ] {
        let mut changed = value.clone();
        match case {
            "root" => changed["root"]["path"] = json!("/untrusted/root"),
            "writable" => changed["root"]["readonly"] = json!(false),
            "mount" => {
                changed["mounts"] =
                    json!([{"destination":"/app","type":"bind","source":"/untrusted/app"}])
            }
            "hook" => changed["hooks"] = json!({"prestart":[{"path":"/untrusted/hook"}]}),
            "annotation" => changed["annotations"] = json!({"untrusted":"value"}),
            "uid" => changed["process"]["user"]["uid"] = json!(0),
            "gid" => changed["process"]["user"]["gid"] = json!(2000),
            "groups" => changed["process"]["user"]["additionalGids"] = json!([2000]),
            "caps" => changed["process"]["capabilities"]["ambient"] = json!(["CAP_SYS_ADMIN"]),
            "nnp" => changed["process"]["noNewPrivileges"] = json!(false),
            "tty" => changed["process"]["terminal"] = json!(true),
            "argv" => changed["process"]["args"] = json!(["/app", "changed"]),
            "env" => changed["process"]["env"].as_array_mut().unwrap().reverse(),
            "cwd" => changed["process"]["cwd"] = json!("/elsewhere"),
            "namespace-path" => changed["linux"]["namespaces"][0]["path"] = json!("/proc/1/ns/mnt"),
            "duplicate-pid" => changed["linux"]["namespaces"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"pid"})),
            "seccomp-default" => {
                changed["linux"]["seccomp"]["defaultAction"] = json!("SCMP_ACT_ALLOW")
            }
            "seccomp-arch" => {
                changed["linux"]["seccomp"]["architectures"] =
                    json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"])
            }
            "seccomp-extra" => changed["linux"]["seccomp"]["syscalls"][0]["names"]
                .as_array_mut()
                .unwrap()
                .push(json!("read")),
            "seccomp-duplicate" => changed["linux"]["seccomp"]["syscalls"][0]["names"]
                .as_array_mut()
                .unwrap()
                .push(json!("write")),
            "seccomp-args" => {
                changed["linux"]["seccomp"]["syscalls"][0]["args"] =
                    json!([{"index":0,"value":1,"op":"SCMP_CMP_EQ"}])
            }
            "resources" => changed["linux"]["resources"] = json!({"pids":{"limit":1}}),
            "umask" => changed["process"]["user"]["umask"] = json!(0),
            _ => unreachable!(),
        }
        let (spec, process) = actual(&changed);
        assert_eq!(
            project_spec(&checked, &spec, &process, &record(&checked)).err(),
            Some(FinalTaskError::SpecRejected),
            "{case}"
        );
    }
}

#[test]
fn final_projection_commits_actual_view_identity_and_checks_candidate_association() {
    let value = raw_candidate();
    let checked = candidate(&serde_json::to_vec(&value).unwrap());
    let (spec, process) = actual(&value);
    let p = record(&checked);
    let first = project_spec(&checked, &spec, &process, &p).unwrap().0;
    for field in ["mount", "image", "executable"] {
        let mut different = p.clone();
        match field {
            "mount" => different.mount_id += 1,
            "image" => different.image_sha384 = "99".repeat(48),
            _ => different.executable_sha384 = "99".repeat(48),
        }
        assert_ne!(
            project_spec(&checked, &spec, &process, &different)
                .unwrap()
                .0,
            first
        );
    }
    let mut wrong = p;
    wrong.candidate_spec_sha384 = "99".repeat(48);
    assert_eq!(
        project_spec(&checked, &spec, &process, &wrong).err(),
        Some(FinalTaskError::SpecRejected)
    );
}

#[test]
fn final_projection_serialization_is_bounded_before_json_allocation() {
    let huge = "x".repeat(4096);
    assert_eq!(
        bounded_value(&huge, 32).err(),
        Some(FinalTaskError::SpecRejected)
    );
    assert_eq!(bounded_value(&json!({"a":1}), 32).unwrap(), json!({"a":1}));
}

#[test]
fn kernel_start_identity_rejects_wrong_pid_and_handles_parenthesized_comm() {
    let pid = std::process::id() as i32;
    assert!(process_start_ticks(pid).unwrap() > 0);
    for invalid in [0, -1] {
        assert_eq!(
            process_start_ticks(invalid),
            Err(FinalTaskError::TaskRejected)
        );
    }
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "123";
    let text = format!("12 (a tricky ) comm) {}", fields.join(" "));
    assert_eq!(parse_start_ticks(&text, 12), Ok(123));
    assert_eq!(
        parse_start_ticks(&text, 13),
        Err(FinalTaskError::TaskRejected)
    );
    assert_eq!(
        parse_start_ticks("12 (broken) S", 12),
        Err(FinalTaskError::TaskRejected)
    );
    fields[19] = "0";
    assert_eq!(
        parse_start_ticks(&format!("12 (x) {}", fields.join(" ")), 12),
        Err(FinalTaskError::TaskRejected)
    );
}

#[test]
fn public_task_data_alone_does_not_satisfy_registration_identity_checks() {
    let mut identity = TaskIdentity {
        container_id: "local:task".into(),
        generation: 1,
        pid: 12,
    };
    assert!(valid_task(&identity, 1));
    identity.container_id = "../../task".into();
    assert!(!valid_task(&identity, 1));
    identity.container_id = "task".into();
    identity.generation = 0;
    assert!(!valid_task(&identity, 1));
    identity.generation = 1;
    identity.pid = 0;
    assert!(!valid_task(&identity, 1));
    identity.pid = 12;
    assert!(!valid_task(&identity, 0));
}

#[test]
fn application_role_comes_only_from_the_signed_admission_profile() {
    assert_eq!(require_application_role("application-init"), Ok(()));
    for role in [
        "pause",
        "helper",
        "init",
        "ephemeral",
        "application",
        "Application-init",
        "",
    ] {
        assert_eq!(
            require_application_role(role),
            Err(FinalTaskError::TaskRejected)
        );
    }
}
