use crate::FILTER_TGIDS;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;

pub(crate) unsafe fn filter_tgids() -> Option<(u32, u32)> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let tgid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xffff_ffff) as u32;

    if FILTER_TGIDS.contains(&tgid) {
        return None;
    }

    Some((tgid, tid))
}
