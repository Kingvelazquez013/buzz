//! Closed vocabulary types for NIP-FI authority: capabilities, object kinds,
//! transports, intents, binding proposals, admission errors, and dependency
//! versions.
//!
//! This module intentionally omits any public construction path for a
//! sealed request context.  `buzz-relay` owns the only sealing orchestration:
//! it creates a crate-private `SealedRequestContext` inside its own
//! `nip_fi` module, which the Rust module system prevents external crates from
//! naming or constructing.
//!
//! ## Type taxonomy
//!
//! - [`RouteCapability`] — server-owned closed capability vocabulary.
//! - [`ProtectedObjectKind`] — closed protected-object namespace.
//! - [`ProofTransport`] — closed transport discriminant.
//! - [`OperationIntent`] — closed intent vocabulary.
//! - [`BindingProvenance`] / [`BindingProposal`] / [`PreparedDependencyVersions`]
//!   — shared preparation/admission data types passed between relay and DB helpers.
//! - [`AdmissionError`] — closed admission failure type; every variant maps
//!   to exactly one [`DenialClass`] (`FI-INV-13`).

use super::denial::DenialClass;
use chrono::{DateTime, Utc};

// ── Route capability vocabulary ───────────────────────────────────────────────

/// Server-owned closed route capability.
///
/// The database code is the stable identifier written to
/// `protected_object_authority.capability`; no other value is valid.
/// WebSocket event ingress (kind-9 channel messages) maps to
/// [`RouteCapability::MessagesWrite`] / code `2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteCapability {
    /// Read messages. DB code: 1.
    MessagesRead,
    /// Write messages (WebSocket event ingress, kind-9). DB code: 2.
    MessagesWrite,
    /// Read channel metadata. DB code: 3.
    ChannelsRead,
    /// Mutate channels. DB code: 4.
    ChannelsWrite,
    /// Channel administration. DB code: 5.
    AdminChannels,
    /// Read user metadata. DB code: 6.
    UsersRead,
    /// Mutate user metadata. DB code: 7.
    UsersWrite,
    /// User administration. DB code: 8.
    AdminUsers,
    /// Read jobs. DB code: 9.
    JobsRead,
    /// Mutate jobs. DB code: 10.
    JobsWrite,
    /// Read subscriptions. DB code: 11.
    SubscriptionsRead,
    /// Mutate subscriptions. DB code: 12.
    SubscriptionsWrite,
    /// Read files. DB code: 13.
    FilesRead,
    /// Write files. DB code: 14.
    FilesWrite,
    /// Read repositories. DB code: 15.
    ReposRead,
    /// Write repositories. DB code: 16.
    ReposWrite,
    /// Read Git objects and refs. DB code: 17.
    GitRead,
    /// Mutate Git objects and refs. DB code: 18.
    GitWrite,
    /// Bounded Git streaming. DB code: 19.
    GitStream,
    /// Read media. DB code: 20.
    MediaRead,
    /// Upload or mutate media. DB code: 21.
    MediaWrite,
    /// Perform moderation operations. DB code: 22.
    Moderation,
    /// Join an audio session. DB code: 23.
    AudioJoin,
    /// Send or receive bounded audio media. DB code: 24.
    AudioMedia,
    /// Read protected discovery data. DB code: 25.
    Discovery,
    /// Read current local binding status. DB code: 26.
    BindingStatus,
    /// Enroll a local binding. DB code: 27.
    BindingEnroll,
    /// Retire a local binding. DB code: 28.
    BindingRetire,
    /// Access the recovery path. DB code: 29.
    Recovery,
}

impl RouteCapability {
    /// Stable database code for `protected_object_authority.capability`.
    pub const fn database_code(self) -> i16 {
        match self {
            Self::MessagesRead => 1,
            Self::MessagesWrite => 2,
            Self::ChannelsRead => 3,
            Self::ChannelsWrite => 4,
            Self::AdminChannels => 5,
            Self::UsersRead => 6,
            Self::UsersWrite => 7,
            Self::AdminUsers => 8,
            Self::JobsRead => 9,
            Self::JobsWrite => 10,
            Self::SubscriptionsRead => 11,
            Self::SubscriptionsWrite => 12,
            Self::FilesRead => 13,
            Self::FilesWrite => 14,
            Self::ReposRead => 15,
            Self::ReposWrite => 16,
            Self::GitRead => 17,
            Self::GitWrite => 18,
            Self::GitStream => 19,
            Self::MediaRead => 20,
            Self::MediaWrite => 21,
            Self::Moderation => 22,
            Self::AudioJoin => 23,
            Self::AudioMedia => 24,
            Self::Discovery => 25,
            Self::BindingStatus => 26,
            Self::BindingEnroll => 27,
            Self::BindingRetire => 28,
            Self::Recovery => 29,
        }
    }

    /// Parse from the stable database code.
    pub fn from_database_code(code: i16) -> Option<Self> {
        match code {
            1 => Some(Self::MessagesRead),
            2 => Some(Self::MessagesWrite),
            3 => Some(Self::ChannelsRead),
            4 => Some(Self::ChannelsWrite),
            5 => Some(Self::AdminChannels),
            6 => Some(Self::UsersRead),
            7 => Some(Self::UsersWrite),
            8 => Some(Self::AdminUsers),
            9 => Some(Self::JobsRead),
            10 => Some(Self::JobsWrite),
            11 => Some(Self::SubscriptionsRead),
            12 => Some(Self::SubscriptionsWrite),
            13 => Some(Self::FilesRead),
            14 => Some(Self::FilesWrite),
            15 => Some(Self::ReposRead),
            16 => Some(Self::ReposWrite),
            17 => Some(Self::GitRead),
            18 => Some(Self::GitWrite),
            19 => Some(Self::GitStream),
            20 => Some(Self::MediaRead),
            21 => Some(Self::MediaWrite),
            22 => Some(Self::Moderation),
            23 => Some(Self::AudioJoin),
            24 => Some(Self::AudioMedia),
            25 => Some(Self::Discovery),
            26 => Some(Self::BindingStatus),
            27 => Some(Self::BindingEnroll),
            28 => Some(Self::BindingRetire),
            29 => Some(Self::Recovery),
            _ => None,
        }
    }
}

// ── Protected-object kind vocabulary ─────────────────────────────────────────

/// Closed protected-object kind namespace — matches migration 0042's
/// `CHECK (object_kind IN (1, 2, 3, 4, 5, 6))` constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedObjectKind {
    /// Domain / community-wide scope. DB code: 1.
    Domain,
    /// Channel resource. DB code: 2.
    Channel,
    /// Repository resource. DB code: 3.
    Repository,
    /// Media resource. DB code: 4.
    Media,
    /// Moderation target. DB code: 5.
    ModerationTarget,
    /// Audio session. DB code: 6.
    AudioSession,
}

impl ProtectedObjectKind {
    /// Stable database code for `protected_object_authority.object_kind`.
    pub const fn database_code(self) -> i16 {
        match self {
            Self::Domain => 1,
            Self::Channel => 2,
            Self::Repository => 3,
            Self::Media => 4,
            Self::ModerationTarget => 5,
            Self::AudioSession => 6,
        }
    }

    /// Parse from the stable database code.
    pub fn from_database_code(code: i16) -> Option<Self> {
        match code {
            1 => Some(Self::Domain),
            2 => Some(Self::Channel),
            3 => Some(Self::Repository),
            4 => Some(Self::Media),
            5 => Some(Self::ModerationTarget),
            6 => Some(Self::AudioSession),
            _ => None,
        }
    }
}

// ── Proof transport discriminant ──────────────────────────────────────────────

/// Closed transport discriminant for the Nostr proof bound to this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofTransport {
    /// NIP-42 WebSocket challenge/response (kind:22242).
    Nip42WebSocket,
    /// NIP-98 HTTP auth (kind:27235).
    Nip98Http,
}

// ── Operation intent vocabulary ───────────────────────────────────────────────

/// Closed operation intent vocabulary. Narrower than capability — each
/// capability has one canonical intent for the purpose of protected-object
/// authority write records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationIntent {
    /// Read access. Intent code: 1.
    Read,
    /// Write/mutation access. Intent code: 2.
    Write,
    /// Administrative action. Intent code: 3.
    Admin,
    /// Enrollment (binding lifecycle). Intent code: 4.
    Enroll,
    /// Retirement (binding lifecycle). Intent code: 5.
    Retire,
    /// Recovery path access. Intent code: 6.
    Recover,
}

impl OperationIntent {
    /// Stable database code.
    pub const fn as_db_code(self) -> i16 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Admin => 3,
            Self::Enroll => 4,
            Self::Retire => 5,
            Self::Recover => 6,
        }
    }
}

// ── Binding proposal ──────────────────────────────────────────────────────────

/// How the binding for this request was located or proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingProvenance {
    /// Binding was located by exact (iss, sub, principal_fingerprint) lookup.
    /// DB code: 1.
    AttestedKey,
    /// Binding was provisioned separately. DB code: 2.
    Provisioned,
    /// Risk-labelled TOFU enrollment. DB code: 3.
    RiskLabelledTofu,
}

impl BindingProvenance {
    /// Stable database code for `identity_bindings.binding_provenance`.
    pub const fn database_code(self) -> i16 {
        match self {
            Self::AttestedKey => 1,
            Self::Provisioned => 2,
            Self::RiskLabelledTofu => 3,
        }
    }
}

/// A proposed binding resolution, passed from the calling layer into the
/// admission path for DB-side validation or creation.
#[derive(Debug, Clone)]
pub struct BindingProposal {
    /// Canonical binding UUID to look up or create.
    pub binding_id: uuid::Uuid,
    /// Provenance class for validation.
    pub provenance: BindingProvenance,
    /// 32-byte principal fingerprint for identity-binding lookup.
    pub principal_fingerprint: [u8; 32],
    /// Optional: known binding version for optimistic concurrency.
    pub known_version: Option<i64>,
}

/// Witness set for dependency versions captured at preparation time.
/// These are re-read inside the SERIALIZABLE window and compared.
#[derive(Debug, Clone)]
pub struct PreparedDependencyVersions {
    /// Policy revision read during preparation.
    pub policy_revision: i64,
    /// Policy `effective_at` timestamp.
    pub policy_effective_at: DateTime<Utc>,
    /// Policy `expires_at`, if set.
    pub policy_expires_at: Option<DateTime<Utc>>,
    /// Binding version read during preparation.
    pub binding_version: i64,
    /// Binding state (1 = active, 2 = retired).
    pub binding_state: i16,
    /// Binding lifecycle revision.
    pub lifecycle_revision: i64,
    /// Binding expiry, if set.
    pub binding_expires_at: Option<DateTime<Utc>>,
    /// Invalidation current_generation at preparation time.
    pub invalidation_generation: i64,
    /// Authority epoch read during preparation (0 = no prior epoch).
    pub authority_epoch: i64,
    /// Authority fence at preparation time (all-zeros = no prior fence).
    pub authority_fence: [u8; 32],
    /// Assertion upstream authority deadline.
    pub assertion_upstream_deadline: DateTime<Utc>,
}

// ── Admission error ───────────────────────────────────────────────────────────

/// Closed, stable admission failure type. Every variant maps to exactly one
/// [`DenialClass`] (`FI-INV-13`). The stable string codes are log/metric keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// Proof event ID has already been used in this community.
    #[error("proof event has already been replayed")]
    ProofReplayed,
    /// The signed event is already committed — exact duplicate, no-op.
    /// Returned by the event-precheck and receipt read-time protocol when the
    /// identical (community_id, event_id) row already exists in the events
    /// table or the receipt ledger.  The caller should treat this as
    /// `was_inserted == false`: roll back, return the stored event as a no-op,
    /// and not count it as an authorization denial.
    #[error("duplicate event — already committed")]
    DuplicateEvent,
    /// The proof freshness deadline has passed.
    #[error("proof event has expired")]
    ProofExpired,
    /// No active binding exists for (iss, sub, community) with matching key.
    #[error("no active binding found")]
    NoActiveBinding,
    /// The binding was found but has been retired.
    #[error("binding has been retired")]
    BindingRetired,
    /// The binding has expired (binding_expires_at ≤ DB transaction_timestamp()).
    #[error("binding has expired")]
    BindingExpired,
    /// The enrollment policy has expired.
    #[error("enrollment policy has expired")]
    PolicyExpired,
    /// The enrollment policy is not yet effective.
    #[error("enrollment policy is not yet effective")]
    PolicyNotYetEffective,
    /// The invalidation generation has advanced past the binding's floor.
    #[error("invalidation generation mismatch")]
    InvalidationGenerationAdvanced,
    /// A required invalidation domain is absent (fail-closed).
    #[error("invalidation domain not activated")]
    InvalidationDomainAbsent,
    /// A required invalidation floor is absent for this binding or selector.
    #[error("invalidation floor absent")]
    InvalidationFloorAbsent,
    /// A prepared deadline did not survive preparation → commit.
    #[error("prepared assertion deadline expired between preparation and admission")]
    PreparedDeadlineExpired,
    /// The re-verified assertion differs on an identity-class field, or a
    /// bounds-class deadline regressed.
    #[error("prepared assertion is not equivalent to current revalidation")]
    AssertionEquivalenceViolation,
    /// Assertion contract IDs changed between preparation and admission.
    #[error("assertion contract IDs changed between preparation and admission")]
    ContractIdChanged,
    /// The community is fenced or in tombstone state — write denied.
    #[error("community write fence denied")]
    CommunityWriteFenced,
    /// The resource is not in a state that permits the requested capability.
    #[error("resource state does not permit this capability")]
    ResourceStateDenied,
    /// The resource version has changed since preparation.
    #[error("resource version changed since preparation")]
    ResourceVersionChanged,
    /// Concurrent identical enrollment converged to a different winner.
    #[error("concurrent enrollment converged to alternate winner")]
    EnrollmentRaceConverged,
    /// Conflicting enrollment attempt; only the private denial class is returned.
    #[error("enrollment conflict denied")]
    EnrollmentConflict,
    /// The authority epoch or fence changed — retry at a new epoch.
    #[error("authority epoch/fence advanced since preparation")]
    EpochFenceAdvanced,
    /// Capacity for authorization audit events is exhausted.
    #[error("authorization audit capacity exhausted")]
    CapacityExhausted,
    /// A PostgreSQL serialization failure (SQLSTATE 40001) — the caller should
    /// retry up to the configured bound.
    #[error("serialization failure — retry")]
    SerializationRetry,
    /// A transient database or infrastructure error. Not retried by the caller.
    #[error("transient database error: {0}")]
    Transient(String),
}

impl AdmissionError {
    /// The single [`DenialClass`] to surface to clients (`FI-INV-13`).
    ///
    /// Multiple distinct server-internal reasons are collapsed to the same
    /// wire class to prevent oracle attacks.
    pub fn denial_class(&self) -> DenialClass {
        match self {
            Self::ProofReplayed
            | Self::DuplicateEvent
            | Self::ProofExpired
            | Self::NoActiveBinding
            | Self::BindingRetired
            | Self::BindingExpired
            | Self::PolicyExpired
            | Self::PolicyNotYetEffective
            | Self::InvalidationGenerationAdvanced
            | Self::InvalidationDomainAbsent
            | Self::InvalidationFloorAbsent
            | Self::PreparedDeadlineExpired
            | Self::AssertionEquivalenceViolation
            | Self::ContractIdChanged
            | Self::CommunityWriteFenced
            | Self::ResourceStateDenied
            | Self::ResourceVersionChanged
            | Self::EnrollmentRaceConverged
            | Self::EnrollmentConflict
            | Self::EpochFenceAdvanced => DenialClass::AuthorizationDenied,
            Self::CapacityExhausted | Self::SerializationRetry | Self::Transient(_) => {
                DenialClass::AuthorizationUnavailable
            }
        }
    }

    /// Stable string code for logging and metrics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProofReplayed => "nip_fi_proof_replayed",
            Self::DuplicateEvent => "nip_fi_duplicate_event",
            Self::ProofExpired => "nip_fi_proof_expired",
            Self::NoActiveBinding => "nip_fi_no_active_binding",
            Self::BindingRetired => "nip_fi_binding_retired",
            Self::BindingExpired => "nip_fi_binding_expired",
            Self::PolicyExpired => "nip_fi_policy_expired",
            Self::PolicyNotYetEffective => "nip_fi_policy_not_yet_effective",
            Self::InvalidationGenerationAdvanced => "nip_fi_invalidation_generation",
            Self::InvalidationDomainAbsent => "nip_fi_domain_absent",
            Self::InvalidationFloorAbsent => "nip_fi_floor_absent",
            Self::PreparedDeadlineExpired => "nip_fi_deadline_expired",
            Self::AssertionEquivalenceViolation => "nip_fi_assertion_equivalence",
            Self::ContractIdChanged => "nip_fi_contract_id_changed",
            Self::CommunityWriteFenced => "nip_fi_community_write_fenced",
            Self::ResourceStateDenied => "nip_fi_resource_state",
            Self::ResourceVersionChanged => "nip_fi_resource_version",
            Self::EnrollmentRaceConverged => "nip_fi_enrollment_converged",
            Self::EnrollmentConflict => "nip_fi_enrollment_conflict",
            Self::EpochFenceAdvanced => "nip_fi_epoch_fence_advanced",
            Self::CapacityExhausted => "nip_fi_capacity_exhausted",
            Self::SerializationRetry => "nip_fi_serialization_retry",
            Self::Transient(_) => "nip_fi_transient",
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_capability_round_trip() {
        let cases = [
            (RouteCapability::MessagesRead, 1i16),
            (RouteCapability::MessagesWrite, 2),
            (RouteCapability::ChannelsRead, 3),
            (RouteCapability::Recovery, 29),
        ];
        for (cap, code) in cases {
            assert_eq!(cap.database_code(), code);
            assert_eq!(RouteCapability::from_database_code(code), Some(cap));
        }
        assert_eq!(RouteCapability::from_database_code(99), None);
    }

    #[test]
    fn protected_object_kind_round_trip() {
        for code in 1i16..=6 {
            let kind = ProtectedObjectKind::from_database_code(code).unwrap();
            assert_eq!(kind.database_code(), code);
        }
        assert_eq!(ProtectedObjectKind::from_database_code(7), None);
    }

    #[test]
    fn admission_error_denial_class_coverage() {
        use DenialClass::*;
        let denied_samples = [
            AdmissionError::ProofReplayed,
            AdmissionError::ProofExpired,
            AdmissionError::NoActiveBinding,
            AdmissionError::EpochFenceAdvanced,
            AdmissionError::CommunityWriteFenced,
        ];
        for e in denied_samples {
            assert_eq!(
                e.denial_class(),
                AuthorizationDenied,
                "{e:?} should be AuthorizationDenied"
            );
        }
        assert_eq!(
            AdmissionError::SerializationRetry.denial_class(),
            AuthorizationUnavailable
        );
        assert_eq!(
            AdmissionError::CapacityExhausted.denial_class(),
            AuthorizationUnavailable
        );
    }

    #[test]
    fn admission_error_code_non_empty() {
        let errors = [
            AdmissionError::ProofReplayed,
            AdmissionError::DuplicateEvent,
            AdmissionError::ProofExpired,
            AdmissionError::NoActiveBinding,
            AdmissionError::BindingRetired,
            AdmissionError::BindingExpired,
            AdmissionError::PolicyExpired,
            AdmissionError::PolicyNotYetEffective,
            AdmissionError::InvalidationGenerationAdvanced,
            AdmissionError::InvalidationDomainAbsent,
            AdmissionError::InvalidationFloorAbsent,
            AdmissionError::PreparedDeadlineExpired,
            AdmissionError::AssertionEquivalenceViolation,
            AdmissionError::ContractIdChanged,
            AdmissionError::CommunityWriteFenced,
            AdmissionError::ResourceStateDenied,
            AdmissionError::ResourceVersionChanged,
            AdmissionError::EnrollmentRaceConverged,
            AdmissionError::EnrollmentConflict,
            AdmissionError::EpochFenceAdvanced,
            AdmissionError::CapacityExhausted,
            AdmissionError::SerializationRetry,
            AdmissionError::Transient("test".to_string()),
        ];
        for e in errors {
            assert!(!e.code().is_empty(), "code should be non-empty for {e:?}");
        }
    }

    #[test]
    fn operation_intent_db_codes_distinct() {
        let intents = [
            OperationIntent::Read,
            OperationIntent::Write,
            OperationIntent::Admin,
            OperationIntent::Enroll,
            OperationIntent::Retire,
            OperationIntent::Recover,
        ];
        let codes: Vec<_> = intents.iter().map(|i| i.as_db_code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            codes.len(),
            sorted.len(),
            "intent db codes must be distinct"
        );
    }

    #[test]
    fn proof_transport_variants_debug() {
        let _ = format!("{:?}", ProofTransport::Nip42WebSocket);
        let _ = format!("{:?}", ProofTransport::Nip98Http);
    }
}
