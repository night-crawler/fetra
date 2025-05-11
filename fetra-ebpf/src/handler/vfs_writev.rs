use crate::bindings::{file, iovec};
use crate::event_ext::EventExt;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_probe_read_user};
use aya_ebpf::programs::FEntryContext;
use bytemuck::Zeroable;
use fetra_common::FileAccessEvent;

const MAX_IOVEC: usize = 31;

pub(crate) unsafe fn try_handle_vfs_writev(ctx: &FEntryContext) -> Result<(), i64> {
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
