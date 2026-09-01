//! NIP-FI federated-identity authorization — assertion verifier, JWKS runtime,
//! startup validation, discovery, and closed authority vocabulary.
//!
//! `buzz-relay` owns the only sealing orchestration (`nip_fi` private module).
//! This crate exports the closed vocabulary types and the admission error type;
//! the sealed request context lives inside buzz-relay and is not exported.

/// The client-attached transport header for federated-identity assertions.
///
/// `Authorization` remains reserved for NIP-98; this separate header avoids
/// conflating authentication schemes at the relay ingress.
pub const CLIENT_ATTACHED_HEADER: &str = "Nostr-Federated-Identity";

pub mod assertion;
pub mod authority;
pub mod config;
pub mod denial;
pub mod discovery;
pub mod jwks;
pub mod startup;
pub mod verifier;

pub use assertion::{
    CanonicalCapabilities, ConfidentialAssertion, FederatedIdentity, RevalidationDependencies,
    VerifiedAssertion,
};
pub use authority::{
    AdmissionError, BindingProposal, BindingProvenance, OperationIntent,
    PreparedDependencyVersions, ProofTransport, ProtectedObjectKind, RouteCapability,
};
pub use config::{
    AssertionPolicyId, ClientSubjectPosture, FreshnessClass, IssuerPolicy, IssuerPolicyError,
    IssuerRegistry, SubjectClass, SubjectClassContract, TokenClass, TransportContractId,
    NOSTR_PUBKEY_CLAIM, OAUTH_CLIENT_ID_CLAIM,
};
pub use denial::DenialClass;
pub use discovery::{
    AssertionFreshnessDiscovery, FederatedIdentityDiscovery, FreshnessClassDiscovery,
};
pub use jwks::{
    HttpJwksFetcher, IssuerJwksConfig, JwksFetchError, JwksFetcher, JwksSourceContract,
    ProductionJwksSource,
};
pub use startup::{validate_nip_fi_config, NipFiMode, NipFiStartupError};
pub use verifier::{AssertionKeySet, FederatedAssertionVerifier, IssuerKeySource, VerifierError};
