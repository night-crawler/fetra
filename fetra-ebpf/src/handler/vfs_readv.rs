use crate::bindings::{file, iovec};
use crate::event_ext::EventExt;
use crate::handler::total_iovec_len;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::{helpers::bpf_get_current_comm, programs::FEntryContext, EbpfContext};
use bytemuck::Zeroable;
use fetra_common::{EventType, FileAccessEvent};

pub(crate) unsafe fn try_handle_vfs_readv(ctx: &FEntryContext) -> Result<(), i64> {
    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let file: *const file = ctx.arg(0);
    let vec: *const iovec = ctx.arg(1);
    let vlen: usize = ctx.arg(2);

    let bytes = total_iovec_len(vec, vlen)?;

    let mut event = FileAccessEvent::zeroed();
    event.event_type = EventType::VfsReadv;
    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = bytes;

    event.populate_from_file(file, ctx.as_ptr())?;

    EVENTS.output(&event, 0)?;
    Ok(())
}
