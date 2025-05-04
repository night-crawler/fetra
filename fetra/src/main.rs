mod process;

use crate::process::ext::EventExt;
use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::{programs::FEntry, Btf, EbpfLoader};
use fetra_common::FileAccessEvent;
use log::{debug, warn};
use std::fmt::Display;
use std::fs;

fn get_ppid(pid: impl Display) -> anyhow::Result<u32> {
    Ok(fs::read_to_string(format!("/proc/{}/stat", pid))?
        .split_whitespace()
        .nth(3)
        .context("Failed to get ppid")?
        .parse::<u32>()?)
}

fn get_ppid_path() -> anyhow::Result<[u32; 8]> {
    let pid = unsafe { libc::getpid() } as u32;
    let mut parent_pid = unsafe { libc::getppid() } as u32;
    let mut pids = [0u32; 8];
    pids[0] = pid;
    pids[1] = parent_pid;

    for pid in pids.iter_mut().skip(2) {
        parent_pid = get_ppid(parent_pid)?;
        if parent_pid == 0 {
            break;
        }
        *pid = parent_pid;
    }

    Ok(pids)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let ppid_path = get_ppid_path()?;
    println!("{:?}", ppid_path);

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut loader = EbpfLoader::new();
    let btf = Btf::from_sys_fs().ok();
    loader
        .btf(btf.as_ref())
        .set_global("FILTER_TGIDS", &ppid_path, true);

    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fetra"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FEntry = ebpf.program_mut("handle_write").unwrap().try_into()?;
    program.load("vfs_write", &btf)?;
    program.attach()?;

    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    
    loop {
        while let Some(item) = ring_buf.next() {
            let event = bytemuck::from_bytes::<FileAccessEvent>(&item);
            match event.process() {
                Ok(_) => {}
                Err(err) => {
                    warn!("Failed to read event: {err}");
                }
            }
        }
    }
}
