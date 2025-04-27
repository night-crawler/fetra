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
mod bindings;

use crate::bindings::{file, super_block};
use aya_ebpf::helpers::bpf_probe_read_kernel;
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

macro_rules! p {
    ($base:expr, $($field:tt).+) => {{
        unsafe { (*$base)$(.$field)+ }
    }};
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
    let sb_ptr: *const super_block = bpf_probe_read_kernel(&(*inode_ptr).i_sb)?;
    // let sb_ptr: *const super_block = p!(inode_ptr, i_sb);
    let dev = bpf_probe_read_kernel(&(*sb_ptr).s_dev)?;

    event.dev = dev;
    event.inode = (*inode_ptr).i_ino;

    // helper call is not allowed in probe
    // bpf_d_path(
    //     &(*file).f_path as *const _ as *mut path,
    //     event.path.as_mut_ptr() as *mut c_char,
    //     event.path.len() as u32,
    // );

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
