//! Read-only PALW certificate-round snapshot derived at the current sink.

use kaspa_consensus_core::{
    palw::{
        PalwBatchStatus, ProviderBondView, palw_audit_epoch_inclusion_window_epochs, palw_certificate_included_within_audit_window,
    },
    palw_audit::{PalwAuditFactsError, PalwAuditRoundFacts, derive_palw_audit_selection},
};
use kaspa_hashes::Hash64;
use kaspa_database::prelude::StoreErrorPredicates;

use super::Consensus;
use crate::{
    model::stores::{
        headers::HeaderStoreReader,
        palw::PalwStoreReader,
        palw_provider_bonds::PalwProviderBondsStoreReader,
        virtual_state::VirtualStateStoreReader,
    },
    processes::palw::resolve_palw_audit_epoch_seed,
};

impl Consensus {
    /// Assemble every consensus-owned input for one proposed certificate round without mutating state.
    ///
    /// The persisted provider registry represents the selected chain at `sink`; evaluating its records
    /// at `audit_beacon_epoch * epoch_len` reconstructs the same frozen active set used by the verifier.
    /// Returning `sink` makes staleness explicit: if it moves, operator tooling must refetch rather than
    /// sign against a provider/view snapshot that a later selected parent need not share.
    pub(crate) fn palw_audit_round_facts_impl(
        &self,
        batch_id: Hash64,
        audit_beacon_epoch: u64,
    ) -> Result<PalwAuditRoundFacts, PalwAuditFactsError> {
        let params = &self.config.params;
        if params.palw_activation_daa_score == u64::MAX {
            return Err(PalwAuditFactsError::Disabled);
        }

        // Hold the virtual-stores read lock through the entire assembly. Virtual commit takes the
        // matching write lock before staging both the new sink and provider-registry mutations and
        // retains it until the RocksDB batch commits. Without this guard a reorg could splice the sink
        // from one virtual state together with the provider registry from another.
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read
            .state
            .get()
            .map_err(|error| PalwAuditFactsError::Store(format!("virtual state: {error:?}")))?;
        let sink = virtual_state.ghostdag_data.selected_parent;
        let sink_daa_score = self
            .storage
            .headers_store
            .get_daa_score(sink)
            .map_err(|error| PalwAuditFactsError::Store(format!("sink header: {error:?}")))?;
        let epoch_len = params.palw_epoch_length_daa.max(1);
        let inclusion_epoch = sink_daa_score / epoch_len;

        let manifest = self.storage.palw_store.batch_manifest(batch_id).map_err(|error| {
            if error.is_key_not_found() {
                PalwAuditFactsError::BatchNotFound(batch_id)
            } else {
                PalwAuditFactsError::Store(format!("batch manifest: {error:?}"))
            }
        })?;
        let view = self
            .storage
            .palw_overlay_view_store
            .view(sink)
            .map_err(|error| PalwAuditFactsError::Store(format!("sink overlay view: {error:?}")))?
            .ok_or(PalwAuditFactsError::OverlayViewUnavailable)?;
        let lifecycle = view.entry(&batch_id).cloned().ok_or(PalwAuditFactsError::BatchNotInSinkView(batch_id))?;
        if !matches!(lifecycle.status, PalwBatchStatus::Committed | PalwBatchStatus::Auditing) {
            return Err(PalwAuditFactsError::BatchNotAuditable(lifecycle.status));
        }

        if audit_beacon_epoch < manifest.registration_epoch || audit_beacon_epoch >= manifest.activation_not_before_epoch {
            return Err(PalwAuditFactsError::AuditEpochOutOfRange {
                audit_epoch: audit_beacon_epoch,
                registration_epoch: manifest.registration_epoch,
                activation_epoch: manifest.activation_not_before_epoch,
            });
        }
        let inclusion_window_epochs = palw_audit_epoch_inclusion_window_epochs(&params.palw_batch_admission);
        if !palw_certificate_included_within_audit_window(audit_beacon_epoch, inclusion_epoch, inclusion_window_epochs) {
            return Err(PalwAuditFactsError::OutsideInclusionWindow { audit_epoch: audit_beacon_epoch, inclusion_epoch });
        }

        let previous_epoch_seed = resolve_palw_audit_epoch_seed(
            &self.storage.headers_store,
            &self.services.reachability_service,
            sink,
            params.palw_activation_daa_score,
            params.palw_epoch_length_daa,
            audit_beacon_epoch,
        )
        .ok_or(PalwAuditFactsError::AuditSeedUnavailable(audit_beacon_epoch))?;

        let mut leaves = Vec::with_capacity(manifest.leaf_count as usize);
        for leaf_index in 0..manifest.leaf_count {
            let leaf = self
                .storage
                .palw_store
                .leaf(batch_id, leaf_index)
                .map_err(|error| {
                    if error.is_key_not_found() {
                        PalwAuditFactsError::LeafMissing { batch_id, leaf_index }
                    } else {
                        PalwAuditFactsError::Store(format!("batch leaf {leaf_index}: {error:?}"))
                    }
                })?;
            leaves.push((*leaf).clone());
        }

        let provider_records = self
            .storage
            .palw_provider_bonds_store
            .read()
            .iterator()
            .map(|result| {
                result
                    .map(|(outpoint, record)| (outpoint, (*record).clone()))
                    .map_err(|error| PalwAuditFactsError::Store(format!("provider registry: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provider_bond_view = ProviderBondView::from_records(provider_records);
        let snapshot_daa_score = audit_beacon_epoch.saturating_mul(epoch_len);
        let selection = derive_palw_audit_selection(
            &previous_epoch_seed,
            &batch_id,
            &provider_bond_view,
            snapshot_daa_score,
            &leaves,
            params.palw_audit_committee_size as usize,
            params.palw_audit_sample_size as u32,
        )?;

        let facts = PalwAuditRoundFacts {
            network_id: params.net.suffix().unwrap_or(0),
            sink,
            sink_daa_score,
            inclusion_epoch,
            batch_id,
            manifest_hash: manifest.content_id(),
            manifest: (*manifest).clone(),
            lifecycle,
            leaves,
            audit_beacon_epoch,
            previous_epoch_seed,
            snapshot_daa_score,
            inclusion_window_epochs,
            committee_size: params.palw_audit_committee_size,
            sample_size: params.palw_audit_sample_size,
            quorum_num: params.palw_audit_quorum_num,
            quorum_den: params.palw_audit_quorum_den,
            selection,
        };
        // This explicit drop is load-bearing: keep the snapshot lock alive past every store read and
        // derivation above instead of allowing non-lexical lifetimes to release it after reading sink.
        drop(virtual_read);
        Ok(facts)
    }
}
