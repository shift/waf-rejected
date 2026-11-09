//! Policy-bundle integrity checks.
//!
//! A bundle is accepted only after all of these hold:
//!
//! - the declared SHA-256 `content_hash` matches the canonical payload hash,
//! - a 32-byte Ed25519 `signature` verifies over `content_hash`,
//! - the signing `key_id` matches the configured key (when set),
//! - `generation` never moves backwards, and
//! - `previous_hash` equals the last accepted `content_hash` for a new
//!   generation (hash-chain continuity).
//!
//! Canonicalisation is deliberately independent of protobuf map ordering:
//! payload fields are length-prefixed and the `features` map is sorted by key.
//! An unsigned or malformed bundle is rejected, never applied.

use sha2::{Digest, Sha256};

use crate::config::DistributedConfig;

use super::distri_waf::{PolicyBundle, PolicyPayload};
use super::traits::DistributedError;

const CONTENT_HASH_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// Last accepted bundle, used for replay and hash-chain checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyVerificationState {
    generation: u64,
    content_hash: [u8; CONTENT_HASH_LEN],
    accepted: bool,
}

impl PolicyVerificationState {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn content_hash(&self) -> Option<[u8; CONTENT_HASH_LEN]> {
        self.accepted.then_some(self.content_hash)
    }
}

/// Decoded verifier settings. `None` means signature verification is
/// disabled *explicitly*; the default configuration always yields `Some`.
pub struct PolicyVerifier {
    public_key: Option<ring::signature::UnparsedPublicKey<Vec<u8>>>,
    key_id: String,
    initial_hash: Option<[u8; CONTENT_HASH_LEN]>,
}

impl std::fmt::Debug for PolicyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyVerifier")
            .field("enabled", &self.public_key.is_some())
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl PolicyVerifier {
    /// Build from config. With `require_policy_signature = true` (the default)
    /// a missing or malformed key is an error, so an operator cannot silently
    /// fall back to unsigned policy.
    pub fn from_config(config: &DistributedConfig) -> Result<Self, DistributedError> {
        let initial_hash = if config.policy_initial_hash.trim().is_empty() {
            None
        } else {
            Some(decode_fixed::<CONTENT_HASH_LEN>(
                &config.policy_initial_hash,
                "policy_initial_hash",
            )?)
        };

        if !config.require_policy_signature {
            return Ok(Self {
                public_key: None,
                key_id: config.policy_signing_key_id.clone(),
                initial_hash,
            });
        }

        if config.policy_signing_public_key.trim().is_empty() {
            return Err(DistributedError::invalid(
                "waf.distributed.require_policy_signature is true but \
                 policy_signing_public_key is empty",
            ));
        }
        let key = decode_fixed::<PUBLIC_KEY_LEN>(
            &config.policy_signing_public_key,
            "policy_signing_public_key",
        )?;
        Ok(Self {
            public_key: Some(ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                key.to_vec(),
            )),
            key_id: config.policy_signing_key_id.clone(),
            initial_hash,
        })
    }

    pub fn signature_required(&self) -> bool {
        self.public_key.is_some()
    }

    /// Verify one bundle and, on success, advance `state`.
    pub fn verify(
        &self,
        bundle: &PolicyBundle,
        state: &mut PolicyVerificationState,
    ) -> Result<[u8; CONTENT_HASH_LEN], DistributedError> {
        if bundle.generation == 0 {
            return Err(DistributedError::invalid(
                "policy bundle generation must be non-zero",
            ));
        }
        if bundle.content_hash.len() != CONTENT_HASH_LEN {
            return Err(DistributedError::invalid(format!(
                "policy bundle content_hash must be {CONTENT_HASH_LEN} bytes, got {}",
                bundle.content_hash.len()
            )));
        }
        let mut declared = [0u8; CONTENT_HASH_LEN];
        declared.copy_from_slice(&bundle.content_hash);

        let payload = bundle
            .payload
            .as_ref()
            .ok_or_else(|| DistributedError::invalid("policy bundle is missing its payload"))?;
        let computed = payload_hash(payload);
        if computed != declared {
            return Err(DistributedError::invalid(
                "policy bundle content_hash does not match the canonical payload",
            ));
        }

        if let Some(public_key) = &self.public_key {
            if bundle.signature.len() != SIGNATURE_LEN {
                return Err(DistributedError::invalid(format!(
                    "policy bundle signature must be {SIGNATURE_LEN} bytes, got {}",
                    bundle.signature.len()
                )));
            }
            if !self.key_id.is_empty() && bundle.key_id != self.key_id {
                return Err(DistributedError::invalid(format!(
                    "policy bundle key_id '{}' does not match configured '{}'",
                    bundle.key_id, self.key_id
                )));
            }
            public_key
                .verify(&declared, &bundle.signature)
                .map_err(|_| {
                    DistributedError::invalid("policy bundle Ed25519 signature is invalid")
                })?;
        } else if !bundle.signature.is_empty() {
            // Signature verification was explicitly disabled, but a signed
            // bundle must still never be silently downgraded.
            tracing::debug!(
                key_id = %bundle.key_id,
                "policy signature present but verification is disabled"
            );
        }

        // Replay: the same generation must present the same content.
        if state.accepted && bundle.generation == state.generation {
            if declared != state.content_hash {
                return Err(DistributedError::invalid(
                    "policy bundle replay for an applied generation has different content",
                ));
            }
            return Ok(declared);
        }
        if state.accepted && bundle.generation < state.generation {
            return Err(DistributedError::invalid(format!(
                "policy bundle generation {} is older than applied {}",
                bundle.generation, state.generation
            )));
        }

        let expected_previous = if state.accepted {
            Some(state.content_hash)
        } else {
            self.initial_hash
        };
        if let Some(expected) = expected_previous {
            if bundle.previous_hash.len() != CONTENT_HASH_LEN
                || bundle.previous_hash.as_slice() != expected.as_slice()
            {
                return Err(DistributedError::invalid(
                    "policy bundle hash chain does not continue from the applied bundle",
                ));
            }
        }

        state.generation = bundle.generation;
        state.content_hash = declared;
        state.accepted = true;
        Ok(declared)
    }
}

/// Deterministic SHA-256 over the canonical policy payload.
pub fn payload_hash(payload: &PolicyPayload) -> [u8; CONTENT_HASH_LEN] {
    let mut hasher = Sha256::new();
    for field in [
        payload.ruleset_uri.as_bytes(),
        payload.ruleset_version.as_bytes(),
        payload.compiled_artifact.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    let mut features: Vec<_> = payload.features.iter().collect();
    features.sort_by(|left, right| left.0.cmp(right.0));
    hasher.update((features.len() as u64).to_le_bytes());
    for (name, enabled) in features {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update([u8::from(*enabled)]);
    }
    hasher.finalize().into()
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N], DistributedError> {
    let value = value.trim();
    let bytes = if let Ok(bytes) = hex::decode(value) {
        bytes
    } else {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|error| {
                DistributedError::invalid(format!(
                    "waf.distributed.{name} is neither hex nor base64: {error}"
                ))
            })?
    };
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        DistributedError::invalid(format!(
            "waf.distributed.{name} must decode to {N} bytes, got {}",
            bytes.len()
        ))
    })
}
