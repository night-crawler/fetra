use crate::bindings::iovec;
use aya_ebpf::helpers::bpf_probe_read_user;

pub(crate) mod filemap_fault;
pub(crate) mod vfs_read;
pub(crate) mod vfs_readv;
pub(crate) mod vfs_write;
pub(crate) mod vfs_writev;

const MAX_IOVEC: usize = 31;

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
