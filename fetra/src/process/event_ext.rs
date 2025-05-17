use crate::types;
use crate::types::fs_type::FsType;
use crate::types::mode::{FileType, Permissions};
use crate::types::Result;
use fetra_common::FileAccessEvent;
use linux_raw_sys::general::S_IFMT;
use std::borrow::Cow;
use std::ffi::{c_char, CStr};

pub trait EventExt {
    fn comm(&self) -> Cow<str>;
    fn path(&self) -> Cow<str>;
    async fn cmdline(&self) -> Result<Cmdline>;

    fn major(&self) -> u32;
    fn minor(&self) -> u32;

    fn file_type(&self) -> Result<FileType>;
    fn perms(&self) -> Permissions;
    fn fs_type(&self) -> Result<FsType>;
    async fn dev_name(&self) -> Result<String>;
}

impl EventExt for FileAccessEvent {
    fn comm(&self) -> Cow<str> {
        unsafe { CStr::from_ptr(self.comm.as_ptr() as *const c_char) }.to_string_lossy()
    }
    
    fn path(&self) -> Cow<str> {
        unsafe { CStr::from_ptr(self.path.as_ptr() as *const c_char) }.to_string_lossy()
    }

    async fn cmdline(&self) -> Result<Cmdline> {
        let cmdline_path = format!("/proc/{}/cmdline", self.tgid);
        let cmdline = tokio::fs::read(cmdline_path).await?;
        Ok(Cmdline::new(cmdline))
    }

    fn major(&self) -> u32 {
        (self.dev >> 20) & 0xfff
    }

    fn minor(&self) -> u32 {
        self.dev & 0xfffff
    }

    fn file_type(&self) -> Result<FileType> {
        Ok(FileType::try_from((self.i_mode as u32) & S_IFMT)?)
    }

    fn perms(&self) -> Permissions {
        Permissions::from(self.i_mode)
    }

    fn fs_type(&self) -> Result<FsType> {
        let magic = u32::try_from(self.s_magic)?;
        let fs_type = FsType::try_from(magic)?;

        Ok(fs_type)
    }

    async fn dev_name(&self) -> Result<String> {
        let major = self.major();
        let minor = self.minor();
        let path = format!("/sys/dev/block/{major}:{minor}/uevent");
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(err) => return Err(types::Error::Path(err, path)),
        };
        for line in content.lines() {
            if let Some(name) = line.strip_prefix("DEVNAME=") {
                return Ok(name.to_string());
            }
        }
        Err(types::Error::DeviceNotFound(self.major(), self.minor()))
    }
}

pub struct Cmdline {
    data: Vec<u8>,
    name_end_index: usize,
}

impl Cmdline {
    fn new(data: Vec<u8>) -> Self {
        let name_end_index = data
            .iter()
            .copied()
            .position(|c| c == 0)
            .unwrap_or(data.len().saturating_sub(1));
        Self {
            data,
            name_end_index,
        }
    }

    pub fn name(&self) -> Cow<str> {
        let name = String::from_utf8_lossy(&self.data[..self.name_end_index]);
        name
    }
}
