use crate::bindings::{file, iovec};
use crate::event_ext::EventExt;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_probe_read_user};
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::EbpfContext;
use bytemuck::Zeroable;
use fetra_common::{EventType, FileAccessEvent};

const MAX_IOVEC: usize = 31;

pub(crate) unsafe fn try_handle_vfs_writev(ctx: &FEntryContext) -> Result<(), i64> {
    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let file: *const file = ctx.arg(0);
    let vec: *const iovec = ctx.arg(1);
    let vlen: usize = ctx.arg(2);

    let bytes = total_iovec_len(vec, vlen)?;

    let mut event = FileAccessEvent::zeroed();
    event.event_type = EventType::VfsWritev;
    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = bytes;
    event.populate_from_file(file, ctx.as_ptr())?;

    EVENTS.output(&event, 0)?;

    Ok(())
}

#[inline(always)]
unsafe fn total_iovec_len(vec: *const iovec, vlen: usize) -> Result<u64, i64> {
    let mut total: u64 = 0;

    let limit = vlen & MAX_IOVEC;

    for i in 0..limit {
        let iov: iovec = bpf_probe_read_user(vec.add(i)).map_err(|e| e as i64)?;
        total = total.wrapping_add(iov.iov_len as u64);
    }

    Ok(total)
}
