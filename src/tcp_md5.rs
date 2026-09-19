//! Linux TCP-MD5 configuration. Keys are installed before connect/listen;
//! accepted sockets inherit authentication from the listening socket.
use crate::{config::Peer, transport::endpoint};
use anyhow::{Context, Result, ensure};
use socket2::SockAddr;
use std::{io, mem, os::fd::AsRawFd};

// Linux UAPI tcp_md5sig, including the reserved/extended fields. libc exposes
// TCP_MD5SIG and MAXKEYLEN but does not expose this structure on all targets.
#[repr(C)]
struct Signature {
    address: libc::sockaddr_storage,
    flags: u8,
    prefix_len: u8,
    key_len: u16,
    if_index: i32,
    key: [u8; libc::TCP_MD5SIG_MAXKEYLEN],
}

/// Install the peer's TCP-MD5 key before connect or listen; do nothing if none is set.
/// Use `index` to scope link-local addresses and erase the temporary key buffer.
pub(crate) fn install(socket: &impl AsRawFd, peer: &Peer, index: u32) -> Result<()> {
    let Some(key) = &peer.md5_password else {
        return Ok(());
    };
    ensure!(
        (1..=libc::TCP_MD5SIG_MAXKEYLEN).contains(&key.as_bytes().len()),
        "invalid TCP-MD5 key length"
    );
    let address = SockAddr::from(endpoint(peer.address, 0, index));
    // SAFETY: all-zero storage is valid for the UAPI fields; zero reserved
    // fields select an exact peer address with ordinary TCP_MD5SIG semantics.
    let mut signature: Signature = unsafe { mem::zeroed() };
    ensure!(
        address.len() as usize <= mem::size_of_val(&signature.address),
        "TCP-MD5 address too large"
    );
    // SAFETY: both buffers are live, non-overlapping, and at least len bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            address.as_ptr().cast::<u8>(),
            (&mut signature.address as *mut libc::sockaddr_storage).cast::<u8>(),
            address.len() as usize,
        );
    }
    signature.key_len = key.as_bytes().len() as u16;
    signature.key[..key.as_bytes().len()].copy_from_slice(key.as_bytes());
    // SAFETY: signature has the Linux UAPI layout and remains live for the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            (&signature as *const Signature).cast(),
            mem::size_of_val(&signature) as _,
        )
    };
    let error = if result < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // The kernel copies the key. Avoid leaving this extra stack copy behind.
    for byte in &mut signature.key {
        // SAFETY: each byte is writable local storage, not aliased elsewhere.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    if let Some(error) = error {
        return Err(error).with_context(|| {
            format!(
                "installing TCP-MD5 for peer {}; kernel TCP_MD5SIG support is required",
                peer.address
            )
        });
    }
    Ok(())
}
