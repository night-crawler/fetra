use crate::bindings::fault_flag::{FAULT_FLAG_MKWRITE, FAULT_FLAG_WRITE};
use crate::bindings::{file, page, super_block, vm_area_struct, vm_fault};
use crate::d_path::d_path_local;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_probe_read_kernel};
use aya_ebpf::programs::FExitContext;
use aya_ebpf::EbpfContext;
use bytemuck::Zeroable;
use core::ptr::copy_nonoverlapping;
use fetra_common::{EventType, FileAccessEvent};

const PAGE_SIZE: u64 = 4096;
const PAGE_ORDER_MASK: u64 = 0x1f;

unsafe fn vmf_file(vmf: *const vm_fault) -> Result<*const file, i64> {
    let vma: *const vm_area_struct = bpf_probe_read_kernel(&(*vmf).__bindgen_anon_1.vma)?;
    Ok(bpf_probe_read_kernel(&(*vma).vm_file)?)
}

#[inline(always)]
unsafe fn is_write(flags: u64) -> bool {
    flags & (FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE) as u64 != 0
}

unsafe fn bytes_from_page(page_ptr: *const page) -> Result<(EventType, u64), i64> {
    if page_ptr.is_null() {
        return Ok((EventType::NullPage, 0));
    }

    let flags: u64 = bpf_probe_read_kernel(&(*page_ptr).flags)?;
    let event_type = if is_write(flags) {
        EventType::MmapWrite
    } else {
        EventType::MmapRead
    };

    let order = flags & PAGE_ORDER_MASK;
    let num_pages = 1u64 << order;

    Ok((event_type, num_pages * PAGE_SIZE))
}

pub unsafe fn try_handle_filemap_fault(ctx: &FExitContext) -> Result<(), i64> {
    let vmf: *const vm_fault = ctx.arg(0);

    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let page_ptr: *const page = bpf_probe_read_kernel(&(*vmf).page)?;
    let (event_type, bytes) = bytes_from_page(page_ptr)?;

    let mut event = FileAccessEvent::zeroed();
    event.event_type = event_type;
    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = bytes;

    let f = vmf_file(vmf)?;

    // TODO: why doesn't it work and I need to read ALL kernel mem manually all the time?
    // event.populate_from_file(f, ctx.as_ptr())?;

    let inode_ptr = bpf_probe_read_kernel(&(*f).f_inode)?;
    let sb_ptr: *const super_block = bpf_probe_read_kernel(&(*inode_ptr).i_sb)?;

    event.dev = bpf_probe_read_kernel(&(*sb_ptr).s_dev)?;
    event.inode = bpf_probe_read_kernel(&(*inode_ptr).i_ino)?;
    event.s_magic = bpf_probe_read_kernel(&(*sb_ptr).s_magic)?;
    event.i_mode = bpf_probe_read_kernel(&(*inode_ptr).i_mode)?;

    let path = bpf_probe_read_kernel(&(*f).f_path)?;

    let (buf, len) = d_path_local(ctx.as_ptr(), path)?;
    copy_nonoverlapping(buf, &mut event.path as *mut _, len.min(event.path.len()));

    EVENTS.output(&event, 0)?;
    Ok(())
}
