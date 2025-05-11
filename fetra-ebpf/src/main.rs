#![allow(static_mut_refs)]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    improper_ctypes,
    clippy::all
)]
#![no_std]
#![no_main]

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    improper_ctypes,
    clippy::all
)]
pub mod bindings;

mod d_path;
mod event_ext;
pub mod ext;
mod helpers;

use crate::bindings::{file, iovec};
use crate::event_ext::EventExt;
use aya_ebpf::helpers::bpf_probe_read_user;
use aya_ebpf::macros::fentry;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::RingBuf,
};
use bytemuck::Zeroable;
use fetra_common::FileAccessEvent;

#[no_mangle]
static mut FILTER_TGIDS: [u32; 16] = [0; 16];

const N_EVENTS: usize = 16 * 1024;
const RB_CAP: u32 = (N_EVENTS * size_of::<FileAccessEvent>()) as u32;

#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(RB_CAP, 0);

#[fentry(function = "handle_vfs_write")]
pub fn handle_vfs_write(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_vfs_write(&ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

unsafe fn filter_tgids() -> Option<(u32, u32)> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let tgid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xffff_ffff) as u32;

    if FILTER_TGIDS.contains(&tgid) {
        return None;
    }

    Some((tgid, tid))
}

unsafe fn try_handle_vfs_write(ctx: &FEntryContext) -> Result<(), i64> {
    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let file: *const file = ctx.arg(0);
    let count: usize = ctx.arg(2);

    let mut event = FileAccessEvent::zeroed();

    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = count as i64;

    event.populate_from_file(file, ctx)?;

    EVENTS.output(&event, 0)?;

    Ok(())
}


#[fentry(function = "handle_vfs_writev")]
pub fn handle_vfs_writev(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_vfs_writev(&ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

unsafe fn try_handle_vfs_writev(ctx: &FEntryContext) -> Result<(), i64> {
    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let file: *const file = ctx.arg(0);
    let vec: *const iovec = ctx.arg(1);
    let vlen: usize = ctx.arg(2);

    let bytes = total_iovec_len(vec, vlen)? as i64;

    let mut ev = FileAccessEvent::zeroed();
    ev.tid = tid;
    ev.tgid = tgid;
    ev.comm = bpf_get_current_comm()?;
    ev.bytes = bytes;
    ev.populate_from_file(file, ctx)?;

    EVENTS.output(&ev, 0)?;

    Ok(())
}

const MAX_IOVEC: usize = 31;
#[inline(always)]
unsafe fn total_iovec_len(vec: *const iovec, vlen: usize) -> Result<usize, i64> {
    let mut total: usize = 0;

    let limit = vlen & MAX_IOVEC;

    for i in 0..MAX_IOVEC {
        if i >= limit {
            break;
        }

        let iov: iovec = bpf_probe_read_user(vec.add(i)).map_err(|e| e as i64)?;

        total = total.wrapping_add(iov.iov_len as usize);
    }

    Ok(total)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
