use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub(super) fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains NUL")
}

pub(super) fn syscall_ok(result: i32) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        bail!("{}", std::io::Error::last_os_error())
    }
}
