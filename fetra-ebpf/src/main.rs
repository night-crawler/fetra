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
mod handler;
mod helpers;
mod macros;

use crate::handler::filemap_fault::try_handle_filemap_fault;
use crate::handler::vfs_read::try_handle_vfs_read;
use crate::handler::vfs_readv::try_handle_vfs_readv;
use crate::handler::vfs_write::try_handle_vfs_write;
use crate::handler::vfs_writev::try_handle_vfs_writev;
use aya_ebpf::macros::{fentry, fexit};
use aya_ebpf::programs::{FEntryContext, FExitContext};
use aya_ebpf::{macros::map, maps::RingBuf};
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

#[fentry(function = "handle_vfs_writev")]
pub fn handle_vfs_writev(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_vfs_writev(&ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[fexit(function = "handle_filemap_fault")]
pub fn handle_filemap_fault(ctx: FExitContext) -> i64 {
    match unsafe { try_handle_filemap_fault(&ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[fentry(function = "vfs_read")]
pub fn handle_vfs_read(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_vfs_read(&ctx) } {
        Ok(_) => 0,
        Err(e) => e,
    }
}

#[fentry(function = "vfs_readv")]
pub fn handle_vfs_readv(ctx: FEntryContext) -> i64 {
    match unsafe { try_handle_vfs_readv(&ctx) } {
        Ok(_) => 0,
        Err(e) => e,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
