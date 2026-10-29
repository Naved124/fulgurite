//! Confidence: how much a fact is believed, and how evidence combines
//! (design document, section 12).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A confidence in `[0, 1]`. NaN and values outside the range cannot be built,
/// so every confidence in the store is a valid probability-like number, and
/// confidences are totally ordered.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(into = "f32", try_from = "f32")]
pub struct Confidence(f32);

impl From<Confidence> for f32 {
    fn from(c: Confidence) -> f32 {
        c.0
    }
}

impl TryFrom<f32> for Confidence {
    type Error = String;

    fn try_from(v: f32) -> Result<Confidence, String> {
        Confidence::new(v).ok_or_else(|| format!("confidence {v} is not in [0, 1]"))
    }
}

/// The four buckets every confidence is shown through (section 12.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Bucket {
    /// Below 0.50: default, fallback, or heuristic only.
    Guess,
    /// 0.50 to 0.79: one piece of evidence, or evidence with known false positives.
    Weak,
    /// 0.80 to 0.99: several independent pieces of evidence agree.
    Strong,
    /// Exactly 1.0: format specification, user decision or observed execution.
    Certain,
}

impl Confidence {
    /// Full confidence.
    pub const CERTAIN: Confidence = Confidence(1.0);
    /// No confidence at all.
    pub const ZERO: Confidence = Confidence(0.0);

    /// A confidence, or `None` for NaN or a value outside `[0, 1]`.
    pub fn new(value: f32) -> Option<Confidence> {
        // `+ 0.0` turns -0.0 into 0.0, so equal values have one representation.
        (0.0..=1.0)
            .contains(&value)
            .then_some(Confidence(value + 0.0))
    }

    /// The number.
    pub fn value(self) -> f32 {
        self.0
    }

    /// The display bucket.
    pub fn bucket(self) -> Bucket {
        match self.0 {
            v if v >= 1.0 => Bucket::Certain,
            v if v >= 0.80 => Bucket::Strong,
            v if v >= 0.50 => Bucket::Weak,
            _ => Bucket::Guess,
        }
    }

    /// Independent supporting evidence (noisy-OR): `1 - Π(1 - wᵢ)`. Two pieces of
    /// 0.6 give 0.84. No evidence gives zero.
    pub fn any_of(weights: impl IntoIterator<Item = Confidence>) -> Confidence {
        let miss: f64 = weights.into_iter().map(|w| 1.0 - f64::from(w.0)).product();
        Confidence::clamped(1.0 - miss)
    }

    /// A derivation: no stronger than the weakest input, scaled by the pass's own
    /// confidence. A strong type built on a guessed function boundary stays a guess.
    pub fn derived(inputs: impl IntoIterator<Item = Confidence>, pass: Confidence) -> Confidence {
        let weakest = inputs.into_iter().fold(1.0f32, |m, c| m.min(c.0));
        Confidence::clamped(f64::from(weakest) * f64::from(pass.0))
    }

    /// Contradicting evidence of weight `w` lowers the confidence to `c × (1 − w)`.
    pub fn contradicted_by(self, w: Confidence) -> Confidence {
        Confidence::clamped(f64::from(self.0) * (1.0 - f64::from(w.0)))
    }

    /// Computed in `f64` and rounded once; the clamp only absorbs rounding.
    fn clamped(v: f64) -> Confidence {
        Confidence(v.clamp(0.0, 1.0) as f32)
    }
}

impl Eq for Confidence {}

impl Ord for Confidence {
    fn cmp(&self, other: &Confidence) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Confidence) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: f32) -> Confidence {
        Confidence::new(v).unwrap()
    }

    #[test]
    fn rejects_values_outside_the_range() {
        assert!(Confidence::new(f32::NAN).is_none());
        assert!(Confidence::new(-0.0001).is_none());
        assert!(Confidence::new(1.0001).is_none());
        assert!(Confidence::new(f32::INFINITY).is_none());
        assert_eq!(Confidence::new(0.0), Some(Confidence::ZERO));
        assert_eq!(Confidence::new(1.0), Some(Confidence::CERTAIN));
        assert_eq!(
            Confidence::new(-0.0).unwrap().cmp(&Confidence::ZERO),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn buckets_follow_the_table() {
        assert_eq!(c(1.0).bucket(), Bucket::Certain);
        assert_eq!(c(0.99).bucket(), Bucket::Strong);
        assert_eq!(c(0.80).bucket(), Bucket::Strong);
        assert_eq!(c(0.79).bucket(), Bucket::Weak);
        assert_eq!(c(0.50).bucket(), Bucket::Weak);
        assert_eq!(c(0.49).bucket(), Bucket::Guess);
        assert_eq!(c(0.0).bucket(), Bucket::Guess);
    }

    #[test]
    fn combining_rules() {
        assert!((Confidence::any_of([c(0.6), c(0.6)]).value() - 0.84).abs() < 1e-6);
        assert_eq!(Confidence::any_of([]), Confidence::ZERO);
        assert_eq!(Confidence::any_of([c(1.0), c(0.1)]), Confidence::CERTAIN);
        let d = Confidence::derived([c(0.9), c(0.4)], c(0.5));
        assert!((d.value() - 0.2).abs() < 1e-6);
        assert_eq!(Confidence::derived([], c(0.7)), c(0.7));
        assert!((c(0.8).contradicted_by(c(0.5)).value() - 0.4).abs() < 1e-6);
    }
}
