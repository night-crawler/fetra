#![allow(static_mut_refs)]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    improper_ctypes,
    clippy::all,
)]

#![no_std]
#![no_main]

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    improper_ctypes,
    clippy::all,
)]
pub mod bindings;

pub mod ext;
mod d_path;
mod helpers;

use crate::bindings::{file, super_block};
use aya_ebpf::macros::fentry;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::RingBuf,
};
use bytemuck::Zeroable;
use core::ptr::copy_nonoverlapping;
use fetra_common::FileAccessEvent;
use crate::d_path::d_path_local;

#[no_mangle]
static mut FILTER_TGIDS: [u32; 8] = [0; 8];

const N_EVENTS: usize = 16 * 1024;
const RB_CAP: u32 = (N_EVENTS * size_of::<FileAccessEvent>()) as u32;

#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(RB_CAP, 0);

#[fentry(function = "handle_write")]
pub fn handle_write(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_write(&ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

unsafe fn try_handle_write(ctx: &FEntryContext) -> Result<(), i64> {
    let file: *const file = ctx.arg(0);
    let count: usize = ctx.arg(2);

    let pid_tgid = bpf_get_current_pid_tgid();

    let tgid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xffff_ffff) as u32;

    if FILTER_TGIDS.contains(&tgid) {
        return Ok(());
    }

    let mut event = FileAccessEvent::zeroed();

    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = count as i64;

    let inode_ptr = (*file).f_inode;
    let sb_ptr: *const super_block = (*inode_ptr). i_sb;
    let dev = (*sb_ptr).s_dev;

    event.dev = dev;
    event.inode = (*inode_ptr).i_ino;
    event.s_magic = (*sb_ptr).s_magic;
    event.i_mode = (*inode_ptr).i_mode;

    let path = (*file).f_path;

    let (buf, len) = d_path_local(ctx, path)?;
    copy_nonoverlapping(buf, &mut event.path as *mut _, len.min(event.path.len()));

    EVENTS.output(&event, 0)?;

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
