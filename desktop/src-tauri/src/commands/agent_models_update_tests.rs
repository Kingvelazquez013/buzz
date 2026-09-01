use super::*;

fn provider_record(deployed: bool) -> ManagedAgentRecord {
    let mut record: ManagedAgentRecord = serde_json::from_value(serde_json::json!({
        "pubkey": "agent", "name": "Agent", "relay_url": "", "acp_command": "",
        "agent_command": "", "agent_args": [], "mcp_command": "",
        "turn_timeout_seconds": 0, "system_prompt": null, "created_at": "",
        "updated_at": "", "last_started_at": null, "last_stopped_at": null,
        "last_exit_code": null, "last_error": null
    }))
    .unwrap();
    record.backend = crate::managed_agents::BackendKind::Provider {
        id: "provider".into(),
        config: serde_json::json!({}),
    };
    record.backend_agent_id = deployed.then(|| "deployment".to_string());
    record
}

#[test]
fn deployed_provider_rejects_access_edits_that_cannot_be_revoked() {
    let error = ensure_access_policy_change_supported(&provider_record(true), true)
        .expect_err("deployed provider access edit must fail closed");
    assert!(error.contains("no explicit stop or revocation acknowledgement"));
}

#[test]
fn undeployed_provider_accepts_access_edits() {
    ensure_access_policy_change_supported(&provider_record(false), true)
        .expect("no running provider deployment can retain stale access");
}

fn local_record() -> ManagedAgentRecord {
    serde_json::from_value(serde_json::json!({
        "pubkey": "local", "name": "Local Agent", "relay_url": "", "acp_command": "",
        "agent_command": "", "agent_args": [], "mcp_command": "",
        "turn_timeout_seconds": 0, "system_prompt": null, "created_at": "",
        "updated_at": "", "last_started_at": null, "last_stopped_at": null,
        "last_exit_code": null, "last_error": null
    }))
    .unwrap()
    // BackendKind deserializes as Local when the field is absent (the json! above).
}

// ── Production-entered seam tests (apply_record_field_updates) ──────────────
//
// These tests call `apply_record_field_updates`, the same function production
// calls inside `update_managed_agent` for the env_vars+effort ordered write.
// They verify:
//   - non-local records are rejected AND the column is NOT mutated;
//   - local set writes to the column and sweeps stale env aliases;
//   - local clear zeroes the column and sweeps stale env aliases;
//   - env_vars applied before effort so no same-request alias re-pins the column.
//
// Deletion proof for the effort guard: removing `ensure_effort_change_supported`
// inside `apply_record_field_updates` makes reject tests return `Ok(())` instead
// of `Err`, and the "record not mutated" assertions fail.
//
// Deletion proof for the apply call: removing the `apply_effort_update` call
// inside `apply_record_field_updates` leaves `effort_level == None` on local-set.
//
// Deletion proof for the env_vars step: removing `apply_env_vars_then_effort_transition`
// inside `apply_record_field_updates` leaves the env alias in `env_vars` on local-set.
//
// Ordering proof: `env_vars` with a stale alias is applied BEFORE effort so the
// alias is stripped; reversing the order leaves both the alias and the new column.
//
// Note: these tests do NOT prove that deleting the `apply_record_field_updates`
// call from the outer `update_managed_agent` Tauri command causes a test failure —
// that outer binding requires Tauri test infrastructure to exercise directly.

#[test]
fn non_local_set_is_rejected_and_record_not_mutated() {
    let mut record = provider_record(false);
    let err = apply_record_field_updates(&mut record, None, false, Some(Some("high".to_string())))
        .expect_err("non-local record must reject effort writes");
    assert!(
        err.contains("remote effort is set at deploy time"),
        "error must explain why non-local effort writes are rejected: {err}"
    );
    // Column must not be touched — the rejection is before mutation.
    assert_eq!(
        record.effort_level, None,
        "non-local record column must be unchanged after a rejected set"
    );
}

#[test]
fn non_local_clear_is_rejected_and_record_not_mutated() {
    // Clear (None inner value) is also rejected for non-local records — the
    // outer Some signals presence; the inner None is the clear sentinel.
    let mut record = provider_record(false);
    let err = apply_record_field_updates(&mut record, None, false, Some(None))
        .expect_err("non-local record effort clear must also be rejected");
    assert!(err.contains("remote effort is set at deploy time"));
    assert_eq!(
        record.effort_level, None,
        "non-local record column must be unchanged after a rejected clear"
    );
}

#[test]
fn local_set_writes_column_and_sweeps_stale_alias() {
    // `apply_record_field_updates` must write `effort_level` for a local record
    // and strip any stale record-scope effort alias. Deleting the
    // `apply_effort_update` call inside leaves `effort_level == None`.
    let mut record = local_record();
    record
        .env_vars
        .insert("GOOSE_THINKING_EFFORT".to_string(), "low".to_string());

    apply_record_field_updates(&mut record, None, false, Some(Some("high".to_string())))
        .expect("local record must accept effort set");

    assert_eq!(
        record.effort_level.as_deref(),
        Some("high"),
        "local set must write the canonical column"
    );
    assert!(
        !record.env_vars.contains_key("GOOSE_THINKING_EFFORT"),
        "local set must sweep the stale record-native alias"
    );
}

#[test]
fn local_clear_zeroes_column_and_sweeps_alias() {
    let mut record = local_record();
    record.effort_level = Some("high".to_string());
    record
        .env_vars
        .insert("GOOSE_THINKING_EFFORT".to_string(), "high".to_string());

    apply_record_field_updates(&mut record, None, false, Some(None))
        .expect("local record must accept effort clear");

    assert_eq!(
        record.effort_level, None,
        "local clear must zero the canonical column"
    );
    assert!(
        !record.env_vars.contains_key("GOOSE_THINKING_EFFORT"),
        "local clear must sweep the stale record-native alias"
    );
}

#[test]
fn absent_effort_is_noop_for_any_backend() {
    // A missing effortLevel field (the common case) must never be rejected and
    // must never touch the column — this is the don't-touch path.
    let mut local = local_record();
    apply_record_field_updates(&mut local, None, false, None)
        .expect("absent effort must pass for local");
    assert_eq!(
        local.effort_level, None,
        "absent effort must not touch local column"
    );

    let mut provider = provider_record(true);
    apply_record_field_updates(&mut provider, None, false, None)
        .expect("absent effort must pass for provider");
    assert_eq!(
        provider.effort_level, None,
        "absent effort must not touch provider column"
    );
}

#[test]
fn env_vars_applied_before_effort_ordering_invariant() {
    // Order is load-bearing: env_vars BEFORE effort column write. A same-request
    // env_vars map containing a stale alias (GOOSE_THINKING_EFFORT=low) alongside
    // an explicit effort set (high) must end with the alias swept — not re-pinned.
    // If env_vars were applied AFTER effort, the alias would survive.
    let mut record = local_record();
    let mut env_vars = std::collections::BTreeMap::new();
    env_vars.insert("GOOSE_THINKING_EFFORT".to_string(), "low".to_string());

    apply_record_field_updates(
        &mut record,
        Some(&env_vars),
        false,
        Some(Some("high".to_string())),
    )
    .expect("ordering test must succeed for local record");

    assert_eq!(
        record.effort_level.as_deref(),
        Some("high"),
        "effort column must be set to the explicit value"
    );
    assert!(
        !record.env_vars.contains_key("GOOSE_THINKING_EFFORT"),
        "alias in the same-request env_vars must be swept before the column is read at launch"
    );
}

// ── Defensive direct-IPC contract ─────────────────────────────────────────────
//
// Non-blocking defensive coverage (Wes/Carl review): a contradictory request
// combining the ACP inherit sentinel in `env_vars` and a non-null effort_level
// must be deterministic — the effort write wins over the sentinel, and the
// sentinel is swept by the alias-removal step so it cannot shadow the column
// at launch time. The shipped renderer suppresses this combination, but the
// backend must not leave an ambiguous state.

#[test]
fn effort_write_sweeps_acp_sentinel_in_env_vars() {
    // A local record whose env_vars contain BUZZ_ACP_EFFORT_LEVEL (e.g. manually
    // set by a user) plus a concurrent explicit effort_level write. The column
    // must be set to the explicit value AND the sentinel must be removed.
    let mut record = local_record();
    record.env_vars.insert(
        "BUZZ_ACP_EFFORT_LEVEL".to_string(),
        "old-sentinel".to_string(),
    );
    apply_record_field_updates(&mut record, None, false, Some(Some("high".to_string())))
        .expect("local record must accept effort set");
    assert_eq!(
        record.effort_level.as_deref(),
        Some("high"),
        "effort write must set the column"
    );
    assert!(
        !record.env_vars.contains_key("BUZZ_ACP_EFFORT_LEVEL"),
        "ACP sentinel in env_vars must be swept by the alias-removal step"
    );
}

#[test]
fn effort_clear_sweeps_acp_sentinel_in_env_vars() {
    // A concurrent clear (None inner value) plus a pre-existing ACP sentinel.
    // After the clear the column is None and the sentinel is gone — no ambiguity.
    let mut record = local_record();
    record.effort_level = Some("high".to_string());
    record.env_vars.insert(
        "BUZZ_ACP_EFFORT_LEVEL".to_string(),
        "old-sentinel".to_string(),
    );
    apply_record_field_updates(&mut record, None, false, Some(None))
        .expect("local record must accept effort clear");
    assert_eq!(
        record.effort_level, None,
        "effort clear must zero the column"
    );
    assert!(
        !record.env_vars.contains_key("BUZZ_ACP_EFFORT_LEVEL"),
        "ACP sentinel in env_vars must be swept on clear"
    );
}
