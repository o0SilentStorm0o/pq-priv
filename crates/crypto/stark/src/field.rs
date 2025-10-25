//! Goldilocks field arithmetic for STARK proofs.
//!
//! Implements finite field GF(p) where p = 2^64 - 2^32 + 1 (Goldilocks prime).
//! This field is STARK-friendly due to:
//! - Small modulus (64-bit, fits in single register)
//! - High 2-adicity (2^32 divides p-1, enables efficient FFT)
//! - Fast reduction (special form modulus)

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Goldilocks prime: p = 2^64 - 2^32 + 1 = 18446744069414584321
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Field element in GF(p) where p = Goldilocks prime.
///
/// Invariant: 0 <= value < GOLDILOCKS_PRIME
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldElement {
    /// Value in Montgomery form for efficient multiplication.
    /// Stored in canonical form (0 <= value < p).
    value: u64,
}

impl FieldElement {
    /// Zero element (additive identity).
    pub const ZERO: Self = Self { value: 0 };

    /// One element (multiplicative identity).
    pub const ONE: Self = Self { value: 1 };

    /// Two element (generator for subgroups).
    pub const TWO: Self = Self { value: 2 };

    /// Create field element from u64 (reduces modulo p).
    pub fn from_u64(value: u64) -> Self {
        Self {
            value: reduce(value),
        }
    }

    /// Create field element from u64 without reduction (unsafe - caller must ensure value < p).
    pub const fn from_canonical_u64(value: u64) -> Self {
        debug_assert!(value < GOLDILOCKS_PRIME);
        Self { value }
    }

    /// Get canonical u64 representation (0 <= value < p).
    pub fn to_canonical_u64(self) -> u64 {
        self.value
    }

    /// Create from bytes (little-endian, 8 bytes).
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let value = u64::from_le_bytes(*bytes);
        Self::from_u64(value)
    }

    /// Convert to bytes (little-endian, 8 bytes).
    pub fn to_bytes(self) -> [u8; 8] {
        self.value.to_le_bytes()
    }

    /// Compute multiplicative inverse (1/self).
    ///
    /// Returns None if self == 0 (zero has no inverse).
    pub fn inverse(self) -> Option<Self> {
        if self.value == 0 {
            return None;
        }
        // Use Fermat's little theorem: a^(p-1) = 1 mod p
        // => a^(-1) = a^(p-2) mod p
        Some(self.pow(GOLDILOCKS_PRIME - 2))
    }

    /// Compute self^exponent using binary exponentiation.
    pub fn pow(self, mut exponent: u64) -> Self {
        let mut result = Self::ONE;
        let mut base = self;

        while exponent > 0 {
            if exponent & 1 == 1 {
                result *= base;
            }
            base = base * base;
            exponent >>= 1;
        }

        result
    }

    /// Double the field element (optimized for Goldilocks).
    pub fn double(self) -> Self {
        let doubled = self.value << 1;
        Self {
            value: if doubled >= GOLDILOCKS_PRIME {
                doubled - GOLDILOCKS_PRIME
            } else {
                doubled
            },
        }
    }

    /// Square the field element.
    pub fn square(self) -> Self {
        self * self
    }

    /// Negate the field element (-self mod p).
    pub fn negate(self) -> Self {
        if self.value == 0 {
            Self::ZERO
        } else {
            Self {
                value: GOLDILOCKS_PRIME - self.value,
            }
        }
    }
}

/// Reduce u64 modulo Goldilocks prime.
///
/// Uses fast reduction algorithm for special form modulus.
#[inline(always)]
fn reduce(value: u64) -> u64 {
    if value < GOLDILOCKS_PRIME {
        value
    } else {
        // For Goldilocks: p = 2^64 - 2^32 + 1
        // If value >= p, then value - p < 2^32 (since value < 2^64)
        value - GOLDILOCKS_PRIME
    }
}

/// Multiply two field elements modulo Goldilocks prime.
///
/// Uses optimized algorithm exploiting Goldilocks structure.
#[inline]
fn mul_internal(a: u64, b: u64) -> u64 {
    // Compute 128-bit product
    let product = (a as u128) * (b as u128);

    // Split into high and low 64 bits
    let low = product as u64;
    let high = (product >> 64) as u64;

    // For Goldilocks p = 2^64 - 2^32 + 1:
    // Reduce (high * 2^64 + low) mod p
    // Since 2^64 ≡ 2^32 - 1 (mod p), we have:
    // high * 2^64 ≡ high * (2^32 - 1) (mod p)
    
    // Compute high * (2^32 - 1) = high * 2^32 - high
    let high_times_2_32 = (high as u128) << 32;
    let adjustment = high_times_2_32 - (high as u128);
    
    // Add low part
    let sum = adjustment + (low as u128);
    
    // Final reduction (may overflow 64 bits again, so reduce twice if needed)
    (sum % (GOLDILOCKS_PRIME as u128)) as u64
}

// ========== Trait Implementations ==========

impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let sum = self.value.wrapping_add(rhs.value);
        Self {
            value: if sum >= GOLDILOCKS_PRIME {
                sum - GOLDILOCKS_PRIME
            } else {
                sum
            },
        }
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        if self.value >= rhs.value {
            Self {
                value: self.value - rhs.value,
            }
        } else {
            Self {
                value: GOLDILOCKS_PRIME - (rhs.value - self.value),
            }
        }
    }
}

impl SubAssign for FieldElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self {
            value: mul_internal(self.value, rhs.value),
        }
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        self.negate()
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_constants() {
        assert_eq!(FieldElement::ZERO.value, 0);
        assert_eq!(FieldElement::ONE.value, 1);
        assert_eq!(FieldElement::TWO.value, 2);
    }

    #[test]
    fn test_addition() {
        let a = FieldElement::from_u64(100);
        let b = FieldElement::from_u64(200);
        let c = a + b;
        assert_eq!(c.value, 300);

        // Test wraparound
        let max = FieldElement::from_u64(GOLDILOCKS_PRIME - 1);
        let one = FieldElement::ONE;
        let wrapped = max + one;
        assert_eq!(wrapped.value, 0);
    }

    #[test]
    fn test_subtraction() {
        let a = FieldElement::from_u64(300);
        let b = FieldElement::from_u64(100);
        let c = a - b;
        assert_eq!(c.value, 200);

        // Test underflow
        let zero = FieldElement::ZERO;
        let one = FieldElement::ONE;
        let neg_one = zero - one;
        assert_eq!(neg_one.value, GOLDILOCKS_PRIME - 1);
    }

    #[test]
    fn test_multiplication() {
        let a = FieldElement::from_u64(123);
        let b = FieldElement::from_u64(456);
        let c = a * b;
        assert_eq!(c.value, 56088);

        // Test identity
        let x = FieldElement::from_u64(12345);
        assert_eq!(x * FieldElement::ONE, x);
        assert_eq!(x * FieldElement::ZERO, FieldElement::ZERO);
    }

    #[test]
    fn test_negation() {
        let a = FieldElement::from_u64(100);
        let neg_a = -a;
        assert_eq!((a + neg_a).value, 0);

        // Test zero
        let zero = FieldElement::ZERO;
        assert_eq!(-zero, zero);
    }

    #[test]
    fn test_inverse() {
        let a = FieldElement::from_u64(17);
        let inv_a = a.inverse().unwrap();
        assert_eq!((a * inv_a).value, 1);

        // Test zero has no inverse
        assert!(FieldElement::ZERO.inverse().is_none());
    }

    #[test]
    fn test_pow() {
        let base = FieldElement::from_u64(2);
        let result = base.pow(10);
        assert_eq!(result.value, 1024);

        // Test Fermat's little theorem: a^(p-1) = 1 mod p
        let a = FieldElement::from_u64(123);
        let result = a.pow(GOLDILOCKS_PRIME - 1);
        assert_eq!(result, FieldElement::ONE);
    }

    #[test]
    fn test_serialization() {
        let a = FieldElement::from_u64(0x1234567890ABCDEF);
        let bytes = a.to_bytes();
        let b = FieldElement::from_bytes(&bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn test_field_axioms() {
        let a = FieldElement::from_u64(17);
        let b = FieldElement::from_u64(23);
        let c = FieldElement::from_u64(31);

        // Commutativity
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));

        // Distributivity
        assert_eq!(a * (b + c), a * b + a * c);

        // Identities
        assert_eq!(a + FieldElement::ZERO, a);
        assert_eq!(a * FieldElement::ONE, a);

        // Inverses
        assert_eq!(a + (-a), FieldElement::ZERO);
        if let Some(inv_a) = a.inverse() {
            assert_eq!(a * inv_a, FieldElement::ONE);
        }
    }

    #[test]
    fn test_double() {
        let a = FieldElement::from_u64(12345);
        let doubled = a.double();
        assert_eq!(doubled, a + a);

        // Test near modulus
        let near_max = FieldElement::from_u64(GOLDILOCKS_PRIME - 100);
        let doubled_max = near_max.double();
        assert_eq!(doubled_max, near_max + near_max);
    }

    #[test]
    fn test_square() {
        let a = FieldElement::from_u64(123);
        let squared = a.square();
        assert_eq!(squared, a * a);
    }
}
