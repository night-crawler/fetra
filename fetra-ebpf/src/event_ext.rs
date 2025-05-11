use crate::bindings::{file, super_block};
use crate::d_path::d_path_local;
use core::ffi::c_void;
use core::ptr::copy_nonoverlapping;
use fetra_common::FileAccessEvent;

pub trait EventExt {
    unsafe fn populate_from_file(&mut self, file: *const file, ctx: *mut c_void)
        -> Result<(), i64>;
}

impl EventExt for FileAccessEvent {
    unsafe fn populate_from_file(
        &mut self,
        file: *const file,
        ctx: *mut c_void,
    ) -> Result<(), i64> {
        let inode_ptr = (*file).f_inode;
        let sb_ptr: *const super_block = (*inode_ptr).i_sb;
        let dev = (*sb_ptr).s_dev;

        self.dev = dev;
        self.inode = (*inode_ptr).i_ino;
        self.s_magic = (*sb_ptr).s_magic;
        self.i_mode = (*inode_ptr).i_mode;

        let path = (*file).f_path;

        let (buf, len) = d_path_local(ctx, path)?;
        copy_nonoverlapping(buf, &mut self.path as *mut _, len.min(self.path.len()));

        Ok(())
    }
}
