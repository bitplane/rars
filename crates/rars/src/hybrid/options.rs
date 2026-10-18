use crate::{Error, Result};

/// Resource envelope for opt-in hybrid compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridProfile {
    Desktop,
    Server,
}

/// Complete encoder architectures retained as explicit experimental controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridArchitecture {
    Hybrid,
    Relationships,
    Streams,
}

/// Hybrid settings. Explicit writer resource ceilings remain authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HybridOptions {
    pub architecture: HybridArchitecture,
    pub profile: HybridProfile,
    pub variant: u8,
    pub dictionary_ceiling: u64,
    pub archive_analysis: bool,
    pub member_order_optimization: bool,
}

impl Default for HybridOptions {
    fn default() -> Self {
        Self::new(HybridProfile::Desktop)
    }
}

impl HybridOptions {
    pub const fn new(profile: HybridProfile) -> Self {
        Self {
            architecture: HybridArchitecture::Hybrid,
            profile,
            variant: 63,
            dictionary_ceiling: match profile {
                HybridProfile::Desktop => 4 * 1024 * 1024,
                HybridProfile::Server => 64 * 1024 * 1024,
            },
            archive_analysis: false,
            member_order_optimization: false,
        }
    }

    pub fn with_variant(mut self, variant: u8) -> Result<Self> {
        if variant > 63 {
            return Err(Error::InvalidArgument("hybrid variant must be in 0..=63"));
        }
        self.variant = variant;
        Ok(self)
    }

    pub const fn with_architecture(mut self, architecture: HybridArchitecture) -> Self {
        self.architecture = architecture;
        self
    }

    pub const fn with_dictionary_ceiling(mut self, ceiling: u64) -> Self {
        self.dictionary_ceiling = ceiling;
        self
    }

    pub const fn with_archive_analysis(mut self, enabled: bool) -> Self {
        self.archive_analysis = enabled;
        self
    }

    pub const fn with_member_order_optimization(mut self, enabled: bool) -> Self {
        self.member_order_optimization = enabled;
        self
    }

    pub const fn profile(self) -> HybridProfile {
        self.profile
    }
    pub const fn variant(self) -> u8 {
        self.variant
    }
    pub const fn dictionary_ceiling(self) -> u64 {
        self.dictionary_ceiling
    }
    pub const fn archive_analysis(self) -> bool {
        self.archive_analysis
    }
    pub const fn member_order_optimization(self) -> bool {
        self.member_order_optimization
    }
    pub const fn decision_window_bytes(self) -> usize {
        256 * 1024
    }
    pub const fn memory_bytes(self) -> u64 {
        match self.profile {
            HybridProfile::Desktop => 256 * 1024 * 1024,
            HybridProfile::Server => 8 * 1024 * 1024 * 1024,
        }
    }
    pub const fn index_cache_bytes(self) -> u64 {
        match self.profile {
            HybridProfile::Desktop => 16 * 1024 * 1024,
            HybridProfile::Server => 256 * 1024 * 1024,
        }
    }
    pub const fn index_disk_bytes(self) -> u64 {
        match self.profile {
            HybridProfile::Desktop => 8 * 1024 * 1024 * 1024,
            HybridProfile::Server => 256 * 1024 * 1024 * 1024,
        }
    }
    pub const fn candidate_states(self) -> usize {
        match self.profile {
            HybridProfile::Desktop => 2,
            HybridProfile::Server => 8,
        }
    }
    pub const fn passes(self) -> usize {
        match self.profile {
            HybridProfile::Desktop => 2,
            HybridProfile::Server => 3,
        }
    }
}

/// Constant-sized statistics of exact witnesses encountered during construction.
/// These are planning hints, not an enumeration of every indexed repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryStats {
    pub witnesses: u64,
    pub matched_bytes: u64,
    pub max_distance: u64,
    /// Byte weights by the smallest power-of-two window covering the distance.
    pub distance_bytes: [u64; 65],
}

impl Default for DictionaryStats {
    fn default() -> Self {
        Self {
            witnesses: 0,
            matched_bytes: 0,
            max_distance: 0,
            distance_bytes: [0; 65],
        }
    }
}

impl DictionaryStats {
    pub fn observe(&mut self, distance: u64, length: u64) {
        if distance == 0 || length == 0 {
            return;
        }
        self.witnesses = self.witnesses.saturating_add(1);
        self.matched_bytes = self.matched_bytes.saturating_add(length);
        self.max_distance = self.max_distance.max(distance);
        let bucket = 64 - (distance - 1).leading_zeros() as usize;
        self.distance_bytes[bucket] = self.distance_bytes[bucket].saturating_add(length);
    }
}

/// A deterministic bounded shortlist preserving the already validated baseline
/// and ceiling. D95 uses power-of-two windows common to RAR5 and RAR7. The caller
/// validates fractional RAR7 baseline/ceiling declarations against its target.
pub fn dictionary_shortlist(
    stats: &DictionaryStats,
    baseline: u64,
    ceiling: u64,
    count: usize,
) -> Result<Vec<u64>> {
    const MIN: u64 = 128 * 1024;
    if count == 0 || ceiling < MIN || baseline < MIN || baseline > ceiling {
        return Err(Error::InvalidArgument(
            "hybrid dictionary shortlist has no legal window",
        ));
    }
    let largest = 1u64 << (63 - ceiling.leading_zeros());
    let mut out = vec![baseline];
    if count == 1 {
        return Ok(out);
    }
    let max_power = largest.ilog2() as usize;
    let total = stats.distance_bytes[..=max_power]
        .iter()
        .map(|&n| u128::from(n))
        .sum::<u128>();
    let mut cumulative = 0u128;
    let mut d95 = MIN;
    for (power, &weight) in stats.distance_bytes[..=max_power].iter().enumerate() {
        cumulative += u128::from(weight);
        if cumulative * 100 >= total * 95 {
            d95 = (1u64 << power).max(MIN);
            break;
        }
    }
    if !out.contains(&d95) {
        out.push(d95);
    }
    if count >= 3 && !out.contains(&ceiling) {
        out.push(ceiling);
    }
    out.sort_unstable();
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DictionaryMeasurement {
    pub dictionary_size: u64,
    pub packed_bytes: u64,
    pub work_units: u64,
    pub memory_bytes: u64,
}

/// Minimize the worst ratio to the best observed size, work and memory.
/// Integer cross-products make ties reproducible without floating point.
pub fn choose_minimax(measurements: &[DictionaryMeasurement]) -> Result<DictionaryMeasurement> {
    let Some(first) = measurements.first().copied() else {
        return Err(Error::InvalidArgument(
            "hybrid minimax needs a measured candidate",
        ));
    };
    let minima = measurements
        .iter()
        .fold(
            [first.packed_bytes, first.work_units, first.memory_bytes],
            |a, m| {
                [
                    a[0].min(m.packed_bytes),
                    a[1].min(m.work_units),
                    a[2].min(m.memory_bytes),
                ]
            },
        )
        .map(|v| v.max(1));
    let score = |m: DictionaryMeasurement| {
        [m.packed_bytes, m.work_units, m.memory_bytes]
            .into_iter()
            .zip(minima)
            .max_by(|&(an, ad), &(bn, bd)| {
                (u128::from(an) * u128::from(bd)).cmp(&(u128::from(bn) * u128::from(ad)))
            })
            .expect("three score dimensions")
    };
    Ok(*measurements
        .iter()
        .min_by(|&&a, &&b| {
            let (an, ad) = score(a);
            let (bn, bd) = score(b);
            (u128::from(an) * u128::from(bd))
                .cmp(&(u128::from(bn) * u128::from(ad)))
                .then_with(|| {
                    (
                        a.dictionary_size,
                        a.packed_bytes,
                        a.work_units,
                        a.memory_bytes,
                    )
                        .cmp(&(
                            b.dictionary_size,
                            b.packed_bytes,
                            b.work_units,
                            b.memory_bytes,
                        ))
                })
        })
        .expect("nonempty measurements"))
}
