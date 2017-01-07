/// Set bit `bit` of `x` on if `toggle` is true, otherwise off.
pub fn bit(bit: u64, x: u64, toggle: bool) -> u64 {
    if toggle {
        x | (1 << bit)
    } else {
        x & !(1 << bit)
    }
}

/// Test whether bit `bit` of `x` is set.
pub fn test_bit(bit: u64, x: u64) -> bool {
    (x >> bit) & 1 == 1
}
