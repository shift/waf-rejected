//! Minimal raw `io_uring` FFI layer used by the network backend.
//!
//! This module intentionally avoids pulling an external crate: the kernel ABI
//! is stable and the subset we need (read/write/accept + registered buffers)
//! is small. Everything here is `unsafe` and only compiled on Linux behind the
//! `io-uring` feature. On setup failure the caller falls back to the standard
//! tokio path; we never panic on unavailable kernels/seccomp.
//!
//! Requirements: Linux >= 5.1 for the ring, >= 5.6 for `IORING_OP_ACCEPT`
//! multishot (>= 5.19 for `IORING_ACCEPT_MULTISHOT`).
#![cfg(all(feature = "io-uring", target_os = "linux"))]
#![allow(non_camel_case_types)]

use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

// ---- kernel ABI -----------------------------------------------------------

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct io_sqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct io_cqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct io_uring_params {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: io_sqring_offsets,
    pub cq_off: io_cqring_offsets,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct io_uring_sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub rw_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub pad2: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct io_uring_cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: usize,
}

// opcodes / flags
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_ENTER_GETEVENTS: u32 = 1;
pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_ACCEPT_MULTISHOT: u32 = 1;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;

const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

// ---- ring ----------------------------------------------------------------

/// Owns one io_uring instance plus its mmap'd rings. Not `Sync`; callers wrap
/// it in a mutex or keep it on a single thread.
pub struct Uring {
    fd: RawFd,
    entries: u32,
    // SQ ring
    sq_ptr: *mut u8,
    sq_len: usize,
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_array: *mut u32,
    sqes: *mut io_uring_sqe,
    // CQ ring
    cq_ptr: *mut u8,
    cq_len: usize,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const io_uring_cqe,
    registered: bool,
}

impl Uring {
    /// Try to create an io_uring. Returns an error (never panics) when the
    /// kernel lacks support or seccomp blocks the syscalls.
    pub fn new(entries: u32) -> io::Result<Self> {
        let mut params: io_uring_params = unsafe { mem::zeroed() };
        params.flags = IORING_SETUP_CQSIZE;
        params.cq_entries = entries.saturating_mul(2).max(entries);

        let fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                entries as libc::c_ulong,
                &mut params as *mut _ as libc::c_ulong,
            ) as RawFd
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SQ ring
        let sq_ring_sz = params.sq_off.array as usize + params.sq_entries as usize * 4;
        let sq_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sq_ring_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                IORING_OFF_SQ_RING as libc::off_t,
            ) as *mut u8
        };
        if sq_ptr == libc::MAP_FAILED as *mut u8 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }

        // CQ ring
        let cq_ring_sz = params.cq_off.cqes as usize
            + params.cq_entries as usize * mem::size_of::<io_uring_cqe>();
        let cq_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                cq_ring_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                IORING_OFF_CQ_RING as libc::off_t,
            ) as *mut u8
        };
        if cq_ptr == libc::MAP_FAILED as *mut u8 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(sq_ptr as *mut _, sq_ring_sz);
                libc::close(fd);
            }
            return Err(e);
        }

        // SQE array
        let sqes_sz = params.sq_entries as usize * mem::size_of::<io_uring_sqe>();
        let sqes = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sqes_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                IORING_OFF_SQES as libc::off_t,
            ) as *mut io_uring_sqe
        };
        if sqes == libc::MAP_FAILED as *mut io_uring_sqe {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(sq_ptr as *mut _, sq_ring_sz);
                libc::munmap(cq_ptr as *mut _, cq_ring_sz);
                libc::close(fd);
            }
            return Err(e);
        }

        let sq_head = unsafe { sq_ptr.add(params.sq_off.head as usize) as *const AtomicU32 };
        let sq_tail = unsafe { sq_ptr.add(params.sq_off.tail as usize) as *const AtomicU32 };
        let sq_mask = unsafe { *(sq_ptr.add(params.sq_off.ring_mask as usize) as *const u32) };
        let sq_array = unsafe { sq_ptr.add(params.sq_off.array as usize) as *mut u32 };
        let cq_head = unsafe { cq_ptr.add(params.cq_off.head as usize) as *const AtomicU32 };
        let cq_tail = unsafe { cq_ptr.add(params.cq_off.tail as usize) as *const AtomicU32 };
        let cq_mask = unsafe { *(cq_ptr.add(params.cq_off.ring_mask as usize) as *const u32) };
        let cqes = unsafe { cq_ptr.add(params.cq_off.cqes as usize) as *const io_uring_cqe };

        Ok(Self {
            fd,
            entries: params.sq_entries,
            sq_ptr,
            sq_len: sq_ring_sz,
            sq_head,
            sq_tail,
            sq_mask,
            sq_array,
            sqes,
            cq_ptr,
            cq_len: cq_ring_sz,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            registered: false,
        })
    }

    /// Raw fd of the ring; useful for `poll`ing completions.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Submit a single SQE. The closure fills the SQE; it runs only if a slot
    /// is free. Returns `true` when queued.
    pub fn push<F>(&self, fill: F) -> bool
    where
        F: FnOnce(&mut io_uring_sqe),
    {
        let head = unsafe { (*self.sq_head).load(Ordering::Acquire) };
        let tail = unsafe { (*self.sq_tail).load(Ordering::Acquire) };
        if tail.wrapping_sub(head) >= self.entries {
            return false;
        }
        let idx = tail & self.sq_mask;
        let sqe = unsafe { &mut *self.sqes.add(idx as usize) };
        *sqe = io_uring_sqe::default();
        fill(sqe);
        unsafe {
            *self.sq_array.add(idx as usize) = idx;
            (*self.sq_tail).store(tail.wrapping_add(1), Ordering::Release);
        }
        true
    }

    /// Submit queued SQEs. When `wait` is non-zero, block until at least that
    /// many completions are available.
    pub fn submit(&self, wait: u32) -> io::Result<u32> {
        let to_submit = unsafe {
            (*self.sq_tail)
                .load(Ordering::Acquire)
                .wrapping_sub((*self.sq_head).load(Ordering::Acquire))
        };
        if to_submit == 0 && wait == 0 {
            return Ok(0);
        }
        let flags = if wait > 0 { IORING_ENTER_GETEVENTS } else { 0 };
        let r = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.fd as libc::c_ulong,
                to_submit as libc::c_ulong,
                wait as libc::c_ulong,
                flags as libc::c_ulong,
                ptr::null::<libc::c_void>(),
                0usize,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as u32)
        }
    }

    /// Return the next completion without advancing the head. Caller must call
    /// [`Self::cqe_seen`] when done with it.
    pub fn peek_cqe(&self) -> Option<io_uring_cqe> {
        let head = unsafe { (*self.cq_head).load(Ordering::Acquire) };
        let tail = unsafe { (*self.cq_tail).load(Ordering::Acquire) };
        if head == tail {
            return None;
        }
        let idx = head & self.cq_mask;
        Some(unsafe { *self.cqes.add(idx as usize) })
    }

    pub fn cqe_seen(&self) {
        let head = unsafe { (*self.cq_head).load(Ordering::Acquire) };
        unsafe { (*self.cq_head).store(head.wrapping_add(1), Ordering::Release) };
    }

    /// Register a set of user buffers with the ring. Used for zero-copy reads.
    pub fn register_buffers(&mut self, bufs: &[iovec]) -> io::Result<()> {
        let r = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd as libc::c_ulong,
                IORING_REGISTER_BUFFERS as libc::c_ulong,
                bufs.as_ptr() as libc::c_ulong,
                bufs.len() as libc::c_ulong,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        self.registered = true;
        Ok(())
    }

    pub fn entries(&self) -> u32 {
        self.entries
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

impl Drop for Uring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sq_ptr as *mut _, self.sq_len);
            libc::munmap(self.cq_ptr as *mut _, self.cq_len);
            libc::munmap(
                self.sqes as *mut _,
                self.entries as usize * mem::size_of::<io_uring_sqe>(),
            );
            libc::close(self.fd);
        }
    }
}

// Safety: the ring owns its mmap; access is serialised by the caller's Mutex.
unsafe impl Send for Uring {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_or_fallback() {
        // Either we get a ring or a clean error; never a panic.
        match Uring::new(16) {
            Ok(ring) => {
                assert!(ring.entries() >= 16);
                assert!(!ring.is_registered());
            }
            Err(e) => {
                // seccomp / older kernel — acceptable in CI containers.
                eprintln!("io_uring unavailable in this environment: {e}");
            }
        }
    }

    #[test]
    fn register_buffers_or_fallback() {
        let Ok(mut ring) = Uring::new(16) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        let mut buf = vec![0u8; 4096];
        let iov = [iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }];
        match ring.register_buffers(&iov) {
            Ok(()) => assert!(ring.is_registered()),
            Err(e) => eprintln!("register_buffers unavailable: {e}"),
        }
    }
}
