//! Bounded, read-only PALW operator snapshot derived at the current sink.

use kaspa_consensus_core::{
    palw::{da::PalwDaChallengeStatusV1, effective_provider_bond_status, provider_bond_release_daa_score},
    palw_probe::{PalwBatchProbe, PalwDaChallengeProbe, PalwProviderBondProbe, PalwStateProbe, PalwStateProbeError},
    tx::TransactionOutpoint,
};
use kaspa_database::prelude::StoreErrorPredicates;
use kaspa_hashes::Hash64;

use super::Consensus;
use crate::model::stores::{
    headers::HeaderStoreReader, palw::PalwStoreReader, palw_da::PalwDaStoreReader,
    palw_provider_bonds::PalwProviderBondsStoreReader, virtual_state::VirtualStateStoreReader,
};

impl Consensus {
    pub(crate) fn palw_state_probe_impl(
        &self,
        batch_id: Option<Hash64>,
        provider_bond: Option<TransactionOutpoint>,
    ) -> Result<PalwStateProbe, PalwStateProbeError> {
        // Keep the sink, fork-local carried view, and selected-chain provider registry under the same
        // snapshot guard. Virtual commit takes the matching write lock while changing those surfaces.
        // PALW blob writes are direct and do not take this lock; their presence fields remain explicitly
        // diagnostic rather than an atomic/fork-scoped acceptance claim.
        let virtual_read = self.virtual_stores.read();
        let virtual_state =
            virtual_read.state.get().map_err(|error| PalwStateProbeError::Store(format!("virtual state: {error:?}")))?;
        let sink = virtual_state.ghostdag_data.selected_parent;
        let sink_daa_score = self
            .storage
            .headers_store
            .get_daa_score(sink)
            .map_err(|error| PalwStateProbeError::Store(format!("sink header: {error:?}")))?;
        let enabled = self.config.params.palw_activation_daa_score != u64::MAX;

        let view = if enabled {
            self.storage
                .palw_overlay_view_store
                .view(sink)
                .map_err(|error| PalwStateProbeError::Store(format!("sink overlay view: {error:?}")))?
        } else {
            None
        };
        let overlay_view_available = view.is_some();

        let batch = match (batch_id, view.as_ref()) {
            (Some(batch_id), Some(view)) => match view.entry(&batch_id).cloned() {
                Some(lifecycle) => {
                    let manifest = match self.storage.palw_store.batch_manifest(batch_id) {
                        Ok(manifest) => Some((*manifest).clone()),
                        Err(error) if error.is_key_not_found() => None,
                        Err(error) => return Err(PalwStateProbeError::Store(format!("batch manifest: {error:?}"))),
                    };
                    // Defense in depth for corrupted/legacy state: the operator RPC remains bounded
                    // even if a lifecycle row claims a leaf count beyond the activated network cap.
                    let scan_limit = lifecycle.leaf_count.min(self.config.params.palw_batch_admission.max_batch_leaves);
                    let leaf_scan_complete = scan_limit == lifecycle.leaf_count;
                    let mut leaf_blobs_present = 0;
                    for leaf_index in 0..scan_limit {
                        if self
                            .storage
                            .palw_store
                            .has_leaf(batch_id, leaf_index)
                            .map_err(|error| PalwStateProbeError::Store(format!("leaf presence: {error:?}")))?
                        {
                            leaf_blobs_present += 1;
                        }
                    }
                    let certificate_blob_present = match lifecycle.cert_hash {
                        Some(cert_hash) => match self.storage.palw_store.certificate(cert_hash) {
                            Ok(_) => true,
                            Err(error) if error.is_key_not_found() => false,
                            Err(error) => {
                                return Err(PalwStateProbeError::Store(format!("certificate presence: {error:?}")));
                            }
                        },
                        None => false,
                    };
                    Some(PalwBatchProbe {
                        batch_id,
                        lifecycle,
                        manifest,
                        leaf_blobs_present,
                        leaf_scan_complete,
                        certificate_blob_present,
                    })
                }
                None => None,
            },
            _ => None,
        };

        // Open DA challenges on the requested bond, read under the same virtual snapshot guard. Bounded
        // by construction: reported only for the one requested outpoint and only for Open challenges.
        let da_challenges = match (provider_bond, enabled) {
            (Some(wanted), true) => {
                let state = self
                    .storage
                    .palw_da_store
                    .read()
                    .state(sink)
                    .map_err(|error| PalwStateProbeError::Store(format!("DA state: {error:?}")))?;
                state
                    .challenges
                    .iter()
                    .filter(|(_, challenge)| {
                        challenge.provider_bond == wanted && matches!(challenge.status, PalwDaChallengeStatusV1::Open)
                    })
                    .map(|(challenge_id, challenge)| PalwDaChallengeProbe {
                        challenge_id: *challenge_id,
                        provider_bond: challenge.provider_bond,
                        object_root: challenge.object_root,
                        chunk_index: challenge.chunk_index,
                        opened_daa_score: challenge.challenge.opened_daa_score,
                        response_deadline_daa_score: challenge.challenge.response_deadline_daa_score,
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        let provider_bond = match provider_bond {
            Some(outpoint) if enabled => match self.storage.palw_provider_bonds_store.read().get(&outpoint) {
                Ok(record) => Some(PalwProviderBondProbe {
                    effective_status: effective_provider_bond_status(&record, sink_daa_score),
                    release_daa_score: provider_bond_release_daa_score(&record, self.config.params.palw_epoch_length_daa),
                    record: (*record).clone(),
                }),
                Err(error) if error.is_key_not_found() => None,
                Err(error) => return Err(PalwStateProbeError::Store(format!("provider bond: {error:?}"))),
            },
            _ => None,
        };

        let probe = PalwStateProbe { enabled, sink, sink_daa_score, overlay_view_available, batch, provider_bond, da_challenges };
        drop(virtual_read);
        Ok(probe)
    }
}
