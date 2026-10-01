/// Wrap every extern "C" entry point in this. A panic that escapes into C
/// is undefined behaviour; catching it here turns it into a normal error
/// return instead.
pub fn guard<F, R>(fallback: R, f: F) -> R
where
    F: FnOnce() -> R,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(fallback)
}
