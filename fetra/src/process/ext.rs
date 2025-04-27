use fetra_common::FileAccessEvent;
use log::warn;
use std::ffi::{c_char, CStr};
use std::fs;
use std::fs::read_dir;
use std::os::unix::fs::MetadataExt;

pub trait EventExt {
    fn process(&self) -> Result<(), super::Error>;
}

impl EventExt for FileAccessEvent {
    fn process(&self) -> Result<(), super::Error> {
        let dir = format!("/proc/{}/fd", self.tgid);
        let dentry = match read_dir(&dir) {
            Ok(dentry) => dentry,
            Err(err) => {
                return Err(super::Error::ReadDir(err, dir));
            }
        };

        for entry in dentry {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Failed to open dir entry {err}");
                    continue;
                }
            };

            let file_name = entry.file_name();

            // entry.metadata() is not the same as fs::metadata() 
            let meta = match fs::metadata(entry.path()) {
                Ok(meta) => meta,
                Err(err) => {
                    warn!("Failed to read metadata at {:?}: {err}", entry.path());
                    continue;
                }
            };

            if meta.dev() != self.dev as u64 || meta.ino() != self.inode {
                continue;
            }
            
            let target = match fs::read_link(entry.path()) {
                Ok(target) => target,
                Err(err) => {
                    warn!("Filed to read link at {:?}: {err}", entry.path());
                    continue;
                }
            };
            let comm =
                unsafe { CStr::from_ptr(self.comm.as_ptr() as *const c_char) }.to_string_lossy();

            println!(
                "tgid={} fd={} -> {comm}; target={}",
                self.tgid,
                file_name.to_string_lossy(),
                target.display()
            );
        }

        Ok(())
    }
}
