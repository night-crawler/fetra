use fetra_common::FileAccessEvent;
use log::warn;
use std::ffi::{c_char, CStr};
use std::os::unix::fs::MetadataExt; // Not used in this snippet, but might be elsewhere

// Import necessary constants from libc
use linux_raw_sys::general::{
    ANON_INODE_FS_MAGIC,
     BPF_FS_MAGIC, CGROUP2_SUPER_MAGIC, DEBUGFS_MAGIC, 
    // DEVPTS_FS_MAGIC,
    EFIVARFS_MAGIC, HUGETLBFS_MAGIC, 
    // MQUEUE_MAGIC,
    NSFS_MAGIC, OVERLAYFS_SUPER_MAGIC,
    PIPEFS_MAGIC, PROC_SUPER_MAGIC, RAMFS_MAGIC, SECURITYFS_MAGIC, SELINUX_MAGIC, SMACK_MAGIC,
    SOCKFS_MAGIC, SYSFS_MAGIC, TMPFS_MAGIC, TRACEFS_MAGIC,
    // VFAT_SUPER_MAGIC,
    BTRFS_SUPER_MAGIC, // Add more as needed
    // File type constants from i_mode (combine with S_IFMT)
    S_IFMT, S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO,
};


fn get_inode_type_desc(magic: u64, mode: u16) -> String {
    let magic_desc = match magic as u32 { 
        ANON_INODE_FS_MAGIC => "anon_inode", 
        PIPEFS_MAGIC => "pipe",
        SOCKFS_MAGIC => "socket",
        TMPFS_MAGIC => "tmpfs",
        DEVPTS_FS_MAGIC => "devpts",
        PROC_SUPER_MAGIC => "procfs",
        SYSFS_MAGIC => "sysfs",
        DEBUGFS_MAGIC => "debugfs",
        SECURITYFS_MAGIC => "securityfs",
        CGROUP2_SUPER_MAGIC => "cgroup2fs",
        BPF_FS_MAGIC => "bpf_fs",
        HUGETLBFS_MAGIC => "hugetlbfs",
        MQUEUE_MAGIC => "mqueue",
        NSFS_MAGIC => "nsfs",
        OVERLAYFS_SUPER_MAGIC => "overlayfs",
        RAMFS_MAGIC => "ramfs",
        SELINUX_MAGIC => "selinuxfs",
        SMACK_MAGIC => "smackfs",
        TRACEFS_MAGIC => "tracefs",
        VFAT_SUPER_MAGIC => "vfat",
        BTRFS_SUPER_MAGIC => "btrfs",
        _ => "",
    };

    if !magic_desc.is_empty() && magic != ANON_INODE_FS_MAGIC as u64 {
        return magic_desc.to_string();
    }

    let file_type = (mode as u32) & S_IFMT;
    let mode_desc = match file_type {
        S_IFIFO => "fifo", 
        S_IFCHR => "char_dev",
        S_IFDIR => "dir", 
        S_IFBLK => "block_dev",
        S_IFREG => {
            if magic == ANON_INODE_FS_MAGIC as u64 {
                "anon_inode_file" // e.g., eventfd, signalfd, sync_file
            } else {
                "regular_file" // If magic was unknown
            }
        }
        S_IFLNK => "symlink",
        S_IFSOCK => "socket", // Should usually be caught by SOCKFS_MAGIC
        _ => "",
    };

    if !mode_desc.is_empty() {
        if magic == ANON_INODE_FS_MAGIC as u64 && mode_desc != "socket" { 
            format!("anon_inode:[{}]", mode_desc)
        } else {
            mode_desc.to_string()
        }
    } else if magic == ANON_INODE_FS_MAGIC as u64 {
        "anon_inode:[unknown_type]".to_string()
    }
    else {
        format!("magic:0x{:x}", magic)
    }
}


pub trait EventExt {
    fn process(&self) -> Result<(), String>;
}

impl EventExt for FileAccessEvent {
    fn process(&self) -> Result<(), String> {
        // Safely get comm string
        let comm_cstr = unsafe { CStr::from_ptr(self.comm.as_ptr() as *const c_char) };
        let comm = comm_cstr.to_string_lossy();
        
        let d_name = unsafe { CStr::from_ptr(self.d_name.as_ptr() as *const c_char) };
        let d_name = d_name.to_string_lossy();
        let name_len = d_name.len();
        
        if d_name.starts_with("/dev") {
            println!("{d_name} {:?}", self.d_name);
        }

         let target_desc= if name_len > 0 {
            String::from_utf8_lossy(&self.d_name[0..name_len]).to_string()
        } else {
            get_inode_type_desc(self.s_magic, self.i_mode)
        };

        let fd_placeholder = format!("inode:{}", self.inode);


        // println!(
        //     "tgid={} dev={} {} -> {}; target={}",
        //     self.tgid,
        //     self.dev, 
        //     fd_placeholder, 
        //     comm,
        //     target_desc,
        // );

        Ok(())
    }
}
