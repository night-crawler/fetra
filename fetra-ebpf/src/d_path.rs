use crate::bindings::{dentry, mount, path, qstr, task_struct, vfsmount};
use aya_ebpf::helpers::{bpf_get_current_task_btf, bpf_probe_read_kernel_buf};
use core::mem::offset_of;

use crate::container_of_mut;
use crate::ext::QstrExt;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::map, maps::PerCpuArray};
use core::slice::from_raw_parts_mut;

pub const MAX_BUF_LEN: usize = 4096;
pub const UNRESOLVED_PATH_COMPONENTS: i32 = 0x02;

const MAX_NAME_LEN: usize = 0xff;

#[repr(C)]
pub struct BufferHeap {
    pub buf: [u8; MAX_BUF_LEN + 256],
}

#[map(name = "BUFFER_HEAP_MAP")]
static mut BUFFER_HEAP_MAP: PerCpuArray<BufferHeap> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn read_mnt_parent(curr_vfsmnt: *mut vfsmount) -> Result<*mut mount, i64> {
    let mount_ptr: *mut mount = container_of_mut!(curr_vfsmnt, mount, mnt);

    let mnt_id_unique_ptr = &(*mount_ptr).mnt_parent;
    let mnt_id_unique_val = bpf_probe_read_kernel(mnt_id_unique_ptr)?;

    Ok(mnt_id_unique_val)
}

#[inline(always)]
unsafe fn is_root(dentry: *const dentry) -> Result<bool, i64> {
    let parent = bpf_probe_read_kernel(&(*dentry).d_parent)?;
    Ok(dentry == parent)
}

struct ResolveContext<'a> {
    ctx: &'a FEntryContext,

    root_dentry: *mut dentry,
    root_vfsmnt: *mut vfsmount,

    curr_dentry: *mut dentry,
    curr_vfsmnt: *mut vfsmount,

    curr_mnt: *mut mount,

    base: *mut u8,
    buf_remainder: usize,
    resolved: bool,
}

impl ResolveContext<'_> {
    unsafe fn resolve(&mut self) -> Result<(), i64> {
        for _ in 0..32 {
            if !self.step()? {
                // info!(self.ctx, "Bailing on step {}", i);
                break;
            }
        }

        Ok(())
    }

    unsafe fn step(&mut self) -> Result<bool, i64> {
        if self.is_resolved() {
            self.resolved = true;
            return Ok(true);
        }

        let curr_mnt_root = bpf_probe_read_kernel(&(*self.curr_vfsmnt).mnt_root)?;
        if self.curr_dentry == curr_mnt_root || is_root(self.curr_dentry)? {
            let parent = bpf_probe_read_kernel(&(*self.curr_mnt).mnt_parent)?;

            if self.curr_mnt != parent {
                self.curr_dentry = bpf_probe_read_kernel(&(*self.curr_mnt).mnt_mountpoint)?;
                self.curr_mnt = parent;
                self.curr_vfsmnt = (&mut (*parent).mnt) as *mut vfsmount;
                // info!(self.ctx, "Going up to parent");
                return Ok(true);
            }

            self.resolved = true;
            return Ok(false);
        }

        let name = bpf_probe_read_kernel(&(*self.curr_dentry).d_name)?;
        self.prepend_name(name)?;

        // info!(self.ctx, "name_len: {}", name.len());

        self.curr_dentry = bpf_probe_read_kernel(&(*self.curr_dentry).d_parent)?;

        Ok(true)
    }

    unsafe fn prepend_name(&mut self, name: qstr) -> Result<(), i64> {
        let mut name_len = name.len() as usize & MAX_NAME_LEN;
        let mut name_ptr = name.name as *mut u8;
        let mut write_slash = true;

        if name_len > self.buf_remainder {
            let trim = name_len - self.buf_remainder;
            name_ptr = name_ptr.wrapping_add(trim);
            name_len = self.buf_remainder;
            write_slash = false;
        }

        let space_needed = name_len + write_slash as usize;

        self.buf_remainder -= space_needed;
        self.buf_remainder &= MAX_BUF_LEN - 1;

        let mut write_ptr = self.base.add(self.buf_remainder);
        if write_slash {
            *write_ptr = b'/';
            write_ptr = write_ptr.add(1);
        }

        let write_slice = from_raw_parts_mut(write_ptr, name_len);
        bpf_probe_read_kernel_buf(name_ptr, write_slice)?;

        Ok(())
    }

    fn is_resolved(&self) -> bool {
        self.resolved
            || (self.root_vfsmnt == self.curr_vfsmnt && self.root_dentry == self.curr_dentry)
    }
}

pub unsafe fn d_path_local(ctx: &FEntryContext, path: path) -> Result<(*mut u8, usize), i64> {
    let Some(heap) = BUFFER_HEAP_MAP.get_ptr_mut(0) else {
        return Err(-1);
    };
    let base = heap as *mut u8;

    let task = bpf_get_current_task_btf() as *mut task_struct;
    let fs = (*task).fs;
    let root = (*fs).root;

    let root_dentry = root.dentry;
    let root_vfsmnt = root.mnt;

    let curr_dentry = path.dentry;
    let curr_vfsmnt = path.mnt;

    let mount_ptr: *mut mount = container_of_mut!(curr_vfsmnt, mount, mnt);

    // let mnt_id_unique_val = read_mnt_parent(curr_vfsmnt)?;

    let mut resolver_context = ResolveContext {
        ctx,
        root_dentry,
        root_vfsmnt,

        curr_dentry,
        curr_vfsmnt,
        curr_mnt: mount_ptr,

        base,
        buf_remainder: MAX_BUF_LEN,
        resolved: false,
    };

    resolver_context.resolve()?;

    // info!(ctx, "buf_remainder: {}", resolver_context.buf_remainder);

    let start = base.add(resolver_context.buf_remainder);
    let len = MAX_BUF_LEN - resolver_context.buf_remainder;

    Ok((start, len))
}
