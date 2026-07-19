use super::{HeaderProcessingContext, HeaderProcessor};
use crate::errors::{BlockProcessResult, RuleError, TwoDimVecDisplay};
use crate::model::services::reachability::ReachabilityService;
use crate::processes::window::WindowManager;
use kaspa_consensus_core::constants::PALW_HEADER_VERSION;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::palw::{COMPUTE_TO_HASH_CAP, compute_headroom};
use kaspa_consensus_core::pow_layer0::POW_ALGO_ID_PALW_REPLICA;
use kaspa_consensus_core::{BlockHash, BlueWorkType};
use std::collections::HashSet;

fn validate_palw_component_work(
    expected_hash_work: BlueWorkType,
    expected_compute_work: BlueWorkType,
    actual_hash_work: BlueWorkType,
    actual_compute_work: BlueWorkType,
) -> BlockProcessResult<()> {
    if expected_hash_work != actual_hash_work || expected_compute_work != actual_compute_work {
        return Err(RuleError::PalwComponentWorkMismatch {
            expected_hash_work,
            expected_compute_work,
            actual_hash_work,
            actual_compute_work,
        });
    }
    Ok(())
}

fn validate_palw_compute_headroom(
    pow_algo_id: u8,
    blue_hash_work: BlueWorkType,
    blue_compute_work: BlueWorkType,
) -> BlockProcessResult<()> {
    if pow_algo_id == POW_ALGO_ID_PALW_REPLICA
        && compute_headroom(blue_hash_work, blue_compute_work, COMPUTE_TO_HASH_CAP) == BlueWorkType::ZERO
    {
        return Err(RuleError::PalwComputeCapExhausted);
    }
    Ok(())
}

impl HeaderProcessor {
    pub fn post_pow_validation(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        self.check_blue_score(ctx, header)?;
        self.check_palw_component_work(ctx, header)?;
        self.check_blue_work(ctx, header)?;
        self.check_median_timestamp(ctx, header)?;
        self.check_mergeset_size_limit(ctx)?;
        self.check_bounded_merge_depth(ctx)?;
        self.check_indirect_parents(ctx, header)
    }

    pub fn check_median_timestamp(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        let (past_median_time, window) = self.window_manager.calc_past_median_time(ctx.ghostdag_data())?;
        ctx.block_window_for_past_median_time = Some(window);

        if header.timestamp <= past_median_time {
            return Err(RuleError::TimeTooOld(header.timestamp, past_median_time));
        }

        Ok(())
    }

    pub fn check_mergeset_size_limit(&self, ctx: &mut HeaderProcessingContext) -> BlockProcessResult<()> {
        let mergeset_size = ctx.ghostdag_data().mergeset_size() as u64;
        let mergeset_size_limit = self.mergeset_size_limit;
        if mergeset_size > mergeset_size_limit {
            return Err(RuleError::MergeSetTooBig(mergeset_size, mergeset_size_limit));
        }
        Ok(())
    }

    fn check_blue_score(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        let gd_blue_score = ctx.ghostdag_data().blue_score;
        if gd_blue_score != header.blue_score {
            return Err(RuleError::UnexpectedHeaderBlueScore(gd_blue_score, header.blue_score));
        }
        Ok(())
    }

    fn check_blue_work(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        let gd_blue_work = ctx.ghostdag_data().blue_work;
        if gd_blue_work != header.blue_work {
            return Err(RuleError::UnexpectedHeaderBlueWork(gd_blue_work, header.blue_work));
        }
        Ok(())
    }

    /// ADR-0039 §5.3/§14.2 clauses 8/15.5: Header-v3 commits the exact GHOSTDAG-derived H/C
    /// decomposition in addition to effective E (`check_blue_work`). Replica blocks are rejected
    /// when the same past-relative state has no remaining compute headroom.
    fn check_palw_component_work(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        if header.version < PALW_HEADER_VERSION {
            return Ok(());
        }

        let ghostdag_data = ctx.ghostdag_data();
        validate_palw_component_work(
            ghostdag_data.blue_hash_work,
            ghostdag_data.blue_compute_work,
            header.blue_hash_work,
            header.blue_compute_work,
        )?;
        validate_palw_compute_headroom(header.pow_algo_id, ghostdag_data.blue_hash_work, ghostdag_data.blue_compute_work)
    }

    pub fn check_indirect_parents(&self, ctx: &mut HeaderProcessingContext, header: &Header) -> BlockProcessResult<()> {
        let expected_block_parents = self.parents_manager.calc_block_parents(ctx.pruning_point, header.direct_parents());
        if header.parents_by_level.expanded_len() != expected_block_parents.expanded_len()
            || !expected_block_parents.expanded_iter().zip(header.parents_by_level.expanded_iter()).all(
                |(expected_level_parents, header_level_parents)| {
                    if header_level_parents.len() != expected_level_parents.len() {
                        return false;
                    }
                    // Optimistic path where both arrays are identical also in terms of order
                    if header_level_parents == expected_level_parents {
                        return true;
                    }
                    HashSet::<&BlockHash>::from_iter(header_level_parents) == HashSet::<&BlockHash>::from_iter(expected_level_parents)
                },
            )
        {
            return Err(RuleError::UnexpectedIndirectParents(
                TwoDimVecDisplay(expected_block_parents.into()),
                TwoDimVecDisplay((&header.parents_by_level).into()),
            ));
        };
        Ok(())
    }

    pub fn check_bounded_merge_depth(&self, ctx: &mut HeaderProcessingContext) -> BlockProcessResult<()> {
        let ghostdag_data = ctx.ghostdag_data();
        let merge_depth_root = self.depth_manager.calc_merge_depth_root(ghostdag_data, ctx.pruning_point);
        let finality_point = self.depth_manager.calc_finality_point(ghostdag_data, ctx.pruning_point);
        let mut kosherizing_blues: Option<Vec<BlockHash>> = None;

        for red in ghostdag_data.mergeset_reds.iter().copied() {
            if self.reachability_service.is_dag_ancestor_of(merge_depth_root, red) {
                continue;
            }
            // Lazy load the kosherizing blocks since this case is extremely rare
            if kosherizing_blues.is_none() {
                kosherizing_blues = Some(self.depth_manager.kosherizing_blues(ghostdag_data, merge_depth_root).collect());
            }
            if !self.reachability_service.is_dag_ancestor_of_any(red, &mut kosherizing_blues.as_ref().unwrap().iter().copied()) {
                return Err(RuleError::ViolatingBoundedMergeDepth);
            }
        }

        ctx.merge_depth_root = Some(merge_depth_root);
        ctx.finality_point = Some(finality_point);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(value: u64) -> BlueWorkType {
        BlueWorkType::from(value)
    }

    #[test]
    fn palw_component_work_requires_exact_decomposition() {
        assert!(validate_palw_component_work(w(100), w(25), w(100), w(25)).is_ok());

        let err = validate_palw_component_work(w(100), w(25), w(99), w(26)).unwrap_err();
        assert!(matches!(
            err,
            RuleError::PalwComponentWorkMismatch {
                expected_hash_work,
                expected_compute_work,
                actual_hash_work,
                actual_compute_work,
            } if expected_hash_work == w(100)
                && expected_compute_work == w(25)
                && actual_hash_work == w(99)
                && actual_compute_work == w(26)
        ));
    }

    #[test]
    fn palw_compute_headroom_rejects_only_replica_at_cap() {
        let cap_compute = w(400);
        assert!(validate_palw_compute_headroom(POW_ALGO_ID_PALW_REPLICA, w(100), w(399)).is_ok());
        assert!(matches!(
            validate_palw_compute_headroom(POW_ALGO_ID_PALW_REPLICA, w(100), cap_compute),
            Err(RuleError::PalwComputeCapExhausted)
        ));
        // The permanent hash-floor lane remains admissible so it can create new headroom.
        assert!(
            validate_palw_compute_headroom(kaspa_consensus_core::pow_layer0::POW_ALGO_ID_BLAKE2B_SHA3, w(100), cap_compute).is_ok()
        );
    }
}
