//! Minimal logging facade. Avoids pulling in `log`/`tracing` until the
//! runtime grows enough to justify it.

#[macro_export]
macro_rules! qlog {
    ($lvl:expr, $($arg:tt)*) => {{
        // Backed by host stderr via the kernel32 stub for now.
        // Real implementation will route through quantum-runtime.
        let _ = $lvl;
        let _ = format_args!($($arg)*);
    }};
}

#[derive(Debug, Clone, Copy)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
