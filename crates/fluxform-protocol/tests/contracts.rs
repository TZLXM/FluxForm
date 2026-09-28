use fluxform_protocol::{
    ApiErrorV1, CategoryV1, ConversionRequestV1, DiagnosticIdV1, ErrorCodeV1, ImageOptionsV1,
    JobEventV1, JobStateV1, OutputTargetV1, OverwritePolicyV1, ProtocolVersionV1,
};

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn committed_contracts_match_the_rust_source() {
    for (relative_path, expected) in fluxform_protocol::exported_contracts() {
        let path = workspace_root().join(relative_path);
        let committed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(committed, expected, "contract drift in {relative_path}");
    }
}

#[test]
fn v1_compatibility_digest_cannot_change_with_normal_regeneration() {
    let frozen =
        std::fs::read_to_string(workspace_root().join("contracts/v1/compatibility.sha256"))
            .unwrap();
    assert_eq!(frozen.trim(), fluxform_protocol::contract_digest());
}

#[test]
fn canonical_fixtures_round_trip_through_their_public_types() {
    let fixtures = fluxform_protocol::canonical_fixtures();

    let request: ConversionRequestV1 =
        serde_json::from_value(fixtures["contracts/v1/fixtures/create-image-job.json"].clone())
            .unwrap();
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        fixtures["contracts/v1/fixtures/create-image-job.json"]
    );

    let completed: JobEventV1 =
        serde_json::from_value(fixtures["contracts/v1/fixtures/completed-image-job.json"].clone())
            .unwrap();
    assert_eq!(
        serde_json::to_value(completed).unwrap(),
        fixtures["contracts/v1/fixtures/completed-image-job.json"]
    );

    let error: ApiErrorV1 = serde_json::from_value(
        fixtures["contracts/v1/fixtures/unsupported-conversion.json"].clone(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        fixtures["contracts/v1/fixtures/unsupported-conversion.json"]
    );
}

#[test]
fn exported_error_schema_constrains_public_messages_and_diagnostic_ids() {
    let contracts = fluxform_protocol::exported_contracts();
    for path in [
        "contracts/v1/error.schema.json",
        "contracts/v1/job-event.schema.json",
    ] {
        let schema = &contracts[path];
        let conditions = if path.ends_with("error.schema.json") {
            &schema["allOf"]
        } else {
            &schema["$defs"]["ApiErrorV1"]["allOf"]
        };
        for code in [
            ErrorCodeV1::UnsupportedInput,
            ErrorCodeV1::UnsupportedConversion,
            ErrorCodeV1::MixedCategory,
            ErrorCodeV1::InvalidOption,
            ErrorCodeV1::FileTooLarge,
            ErrorCodeV1::QuotaExceeded,
            ErrorCodeV1::QueueFull,
            ErrorCodeV1::FfprobeFailed,
            ErrorCodeV1::ConversionFailed,
            ErrorCodeV1::OutputTooLarge,
            ErrorCodeV1::Timeout,
            ErrorCodeV1::Cancelled,
            ErrorCodeV1::Interrupted,
            ErrorCodeV1::StorageUnavailable,
        ] {
            let serialized_code = serde_json::to_value(code).unwrap();
            let message = code_to_public_message(serialized_code.as_str().unwrap());
            let matching_condition = conditions.as_array().unwrap().iter().find(|condition| {
                condition["if"]["properties"]["code"]["const"] == serialized_code
            });
            assert_eq!(
                matching_condition.unwrap()["then"]["properties"]["message"]["const"],
                message,
                "{path}"
            );
        }
        assert_eq!(
            schema["$defs"]["DiagnosticIdV1"]["pattern"], "^diag_[A-Za-z0-9_-]+$",
            "{path}"
        );
        assert_eq!(
            schema["$defs"]["DiagnosticIdV1"]["maxLength"], 128,
            "{path}"
        );
    }
}

#[test]
fn conversion_request_schema_rejects_extra_output_target_fields() {
    let schema =
        &fluxform_protocol::exported_contracts()["contracts/v1/conversion-request.schema.json"];
    let validator = jsonschema::validator_for(schema).unwrap();
    let mut request = serde_json::to_value(valid_request()).unwrap();
    request["output_target"]["path"] = serde_json::json!(r"C:\server\escape.png");

    assert!(!validator.is_valid(&request));
}

fn code_to_public_message(code: &str) -> &'static str {
    match code {
        "unsupported_input" => "input format is not supported",
        "unsupported_conversion" => "requested conversion is not supported",
        "mixed_category" => "inputs must use one conversion category",
        "invalid_option" => "one or more conversion options are invalid",
        "file_too_large" => "input exceeds the allowed size",
        "quota_exceeded" => "conversion quota has been exceeded",
        "queue_full" => "conversion queue is full",
        "ffprobe_failed" => "media inspection failed",
        "conversion_failed" => "conversion failed",
        "output_too_large" => "output exceeds the allowed size",
        "timeout" => "conversion timed out",
        "cancelled" => "conversion was cancelled",
        "interrupted" => "conversion was interrupted",
        "storage_unavailable" => "artifact storage is unavailable",
        _ => unreachable!(),
    }
}

fn valid_request() -> ConversionRequestV1 {
    ConversionRequestV1 {
        protocol_version: ProtocolVersionV1::V1,
        input_ids: vec!["input_01".to_owned()],
        category: CategoryV1::Image,
        output_format: "png".to_owned(),
        output_target: OutputTargetV1::ManagedArtifact,
        overwrite_policy: OverwritePolicyV1::Reject,
        options: Default::default(),
        client_context: Default::default(),
    }
}

#[test]
fn managed_artifact_target_serializes_without_a_filesystem_path() {
    let json = serde_json::to_value(valid_request()).unwrap();
    assert_eq!(json["output_target"]["kind"], "managed_artifact");
    assert!(json.to_string().find("path").is_none());
}

#[test]
fn managed_artifact_target_rejects_a_client_supplied_path() {
    let mut value = serde_json::to_value(valid_request()).unwrap();
    value["output_target"]["path"] = serde_json::json!(r"C:\server\escape.png");
    assert!(serde_json::from_value::<ConversionRequestV1>(value).is_err());
}

#[test]
fn error_codes_use_stable_snake_case_values() {
    let cases = [
        (ErrorCodeV1::UnsupportedInput, "unsupported_input"),
        (ErrorCodeV1::UnsupportedConversion, "unsupported_conversion"),
        (ErrorCodeV1::MixedCategory, "mixed_category"),
        (ErrorCodeV1::InvalidOption, "invalid_option"),
        (ErrorCodeV1::FileTooLarge, "file_too_large"),
        (ErrorCodeV1::QuotaExceeded, "quota_exceeded"),
        (ErrorCodeV1::QueueFull, "queue_full"),
        (ErrorCodeV1::FfprobeFailed, "ffprobe_failed"),
        (ErrorCodeV1::ConversionFailed, "conversion_failed"),
        (ErrorCodeV1::OutputTooLarge, "output_too_large"),
        (ErrorCodeV1::Timeout, "timeout"),
        (ErrorCodeV1::Cancelled, "cancelled"),
        (ErrorCodeV1::Interrupted, "interrupted"),
        (ErrorCodeV1::StorageUnavailable, "storage_unavailable"),
    ];

    for (code, expected) in cases {
        assert_eq!(serde_json::to_value(code).unwrap(), expected);
    }
}

#[test]
fn deserialization_rejects_any_version_other_than_v1() {
    let mut value = serde_json::to_value(valid_request()).unwrap();
    value["protocol_version"] = serde_json::json!("v2");
    assert!(serde_json::from_value::<ConversionRequestV1>(value).is_err());
}

#[test]
fn protocol_version_is_required_and_accepts_only_v1() {
    let value = serde_json::to_value(valid_request()).unwrap();
    assert_eq!(value["protocol_version"], "v1");

    for invalid_version in [
        serde_json::json!("v2"),
        serde_json::json!(""),
        serde_json::json!(1),
    ] {
        let mut invalid = value.clone();
        invalid["protocol_version"] = invalid_version;
        assert!(serde_json::from_value::<ConversionRequestV1>(invalid).is_err());
    }

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("protocol_version");
    assert!(serde_json::from_value::<ConversionRequestV1>(missing).is_err());
}

#[test]
fn unknown_request_fields_are_rejected() {
    let mut value = serde_json::to_value(valid_request()).unwrap();
    value["server_output_path"] = serde_json::json!(r"C:\server\escape.png");
    assert!(serde_json::from_value::<ConversionRequestV1>(value).is_err());
}

#[test]
fn every_job_event_contains_job_id_and_positive_revision() {
    let error = ApiErrorV1::new(ErrorCodeV1::ConversionFailed);
    let events = [
        (
            JobEventV1::StateChanged {
                job_id: "job_01".to_owned(),
                revision: 1,
                state: JobStateV1::Validating,
            },
            "job.state_changed",
        ),
        (
            JobEventV1::Progress {
                job_id: "job_01".to_owned(),
                revision: 2,
                progress_percent: 25,
            },
            "job.progress",
        ),
        (
            JobEventV1::Warning {
                job_id: "job_01".to_owned(),
                revision: 3,
                message: "alpha will be composited".to_owned(),
            },
            "job.warning",
        ),
        (
            JobEventV1::Completed {
                job_id: "job_01".to_owned(),
                revision: 4,
                artifact_id: "artifact_01".to_owned(),
            },
            "job.completed",
        ),
        (
            JobEventV1::Failed {
                job_id: "job_01".to_owned(),
                revision: 5,
                error,
            },
            "job.failed",
        ),
        (
            JobEventV1::QueuePositionChanged {
                job_id: "job_01".to_owned(),
                revision: 6,
                position: 2,
            },
            "queue.position_changed",
        ),
    ];

    for (event, expected_type) in events {
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["type"], expected_type);
        assert_eq!(value["job_id"], "job_01");
        assert!(value["revision"].as_u64().unwrap() > 0);
    }
}

#[test]
fn zero_job_event_revision_is_rejected() {
    let event = JobEventV1::StateChanged {
        job_id: "job_01".to_owned(),
        revision: 0,
        state: JobStateV1::Created,
    };
    assert!(serde_json::to_value(event).is_err());

    let value = serde_json::json!({
        "type": "job.state_changed",
        "job_id": "job_01",
        "revision": 0,
        "state": "created"
    });
    assert!(serde_json::from_value::<JobEventV1>(value).is_err());
}

#[test]
fn cancelling_is_distinct_from_terminal_states() {
    let cancelling = serde_json::to_value(JobStateV1::Cancelling).unwrap();
    for terminal in [
        JobStateV1::Completed,
        JobStateV1::Failed,
        JobStateV1::Cancelled,
        JobStateV1::Interrupted,
    ] {
        assert_ne!(serde_json::to_value(terminal).unwrap(), cancelling);
    }
}

#[test]
fn api_errors_expose_only_stable_redacted_fields() {
    let value = serde_json::to_value(ApiErrorV1::with_diagnostic_id(
        ErrorCodeV1::FfprobeFailed,
        DiagnosticIdV1::new("diag_01HXYZ").unwrap(),
    ))
    .unwrap();

    assert_eq!(value["code"], "ffprobe_failed");
    assert_eq!(value["message"], "media inspection failed");
    assert_eq!(value["diagnostic_id"], "diag_01HXYZ");
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert!(value.get("command_line").is_none());
    assert!(value.get("path").is_none());

    let without_diagnostic = serde_json::to_value(ApiErrorV1::new(ErrorCodeV1::Timeout)).unwrap();
    assert!(without_diagnostic.get("diagnostic_id").is_none());
}

#[test]
fn api_errors_reject_sensitive_messages_during_deserialization() {
    for message in [
        r"failed to inspect C:\server\secret.mov",
        "failed to inspect /srv/media/secret.mov",
        "ffmpeg -i input.mov output.mp4",
    ] {
        let value = serde_json::json!({
            "code": "ffprobe_failed",
            "message": message
        });
        assert!(serde_json::from_value::<ApiErrorV1>(value).is_err());
    }
}

#[test]
fn api_errors_reject_sensitive_diagnostic_ids_during_deserialization() {
    for diagnostic_id in [
        r"C:\server\secret.mov",
        "/srv/media/secret.mov",
        "ffmpeg -i input.mov output.mp4",
    ] {
        let value = serde_json::json!({
            "code": "ffprobe_failed",
            "message": "media inspection failed",
            "diagnostic_id": diagnostic_id
        });
        assert!(serde_json::from_value::<ApiErrorV1>(value).is_err());
    }
}

#[test]
fn api_errors_prevent_sensitive_public_strings_from_construction() {
    for sensitive_value in [
        r"C:\server\secret.mov",
        "/srv/media/secret.mov",
        "ffmpeg -i secret.mov output.mp4",
    ] {
        assert!(DiagnosticIdV1::new(sensitive_value).is_err());
    }

    let value = serde_json::to_value(ApiErrorV1::new(ErrorCodeV1::ConversionFailed)).unwrap();
    assert_eq!(value["message"], "conversion failed");
    assert!(!value.to_string().contains("secret.mov"));
}

#[test]
fn image_orientation_is_applied_by_default() {
    assert!(ImageOptionsV1::default().apply_orientation);
}
