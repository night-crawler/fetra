use crate::bindings::file;
use crate::event_ext::EventExt;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::{helpers::bpf_get_current_comm, programs::FEntryContext, EbpfContext};
use bytemuck::Zeroable;
use fetra_common::{EventType, FileAccessEvent};

pub(crate) unsafe fn try_handle_vfs_read(ctx: &FEntryContext) -> Result<(), i64> {
    let Some((tgid, tid)) = filter_tgids() else {
        return Ok(());
    };

    let file: *const file = ctx.arg(0);
    let count: u64 = ctx.arg(2);

    let mut event = FileAccessEvent::zeroed();
    event.event_type = EventType::VfsRead;
    event.tid = tid;
    event.tgid = tgid;
    event.comm = bpf_get_current_comm()?;
    event.bytes = count;

    event.populate_from_file(file, ctx.as_ptr())?;

    EVENTS.output(&event, 0)?;
    Ok(())
}
