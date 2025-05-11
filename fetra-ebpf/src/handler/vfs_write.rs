use crate::bindings::file;
use crate::event_ext::EventExt;
use crate::helpers::filter_tgids;
use crate::EVENTS;
use aya_ebpf::helpers::bpf_get_current_comm;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::EbpfContext;
use bytemuck::Zeroable;
use fetra_common::FileAccessEvent;

pub(crate) unsafe fn try_handle_vfs_write(ctx: &FEntryContext) -> Result<(), i64> {
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

    event.populate_from_file(file, ctx.as_ptr())?;

    EVENTS.output(&event, 0)?;

    Ok(())
}
