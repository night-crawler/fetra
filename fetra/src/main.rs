mod ext;
mod process;
mod types;

use crate::ext::EbpfExt;
use crate::process::aggregator::Aggregator;
use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::FExit;
use aya::{programs::FEntry, Btf, EbpfLoader};
use fetra_common::FileAccessEvent;
use log::{debug, info, warn};
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use std::fmt::Display;
use std::fs;
use std::time::Duration;
use tokio::io::unix::AsyncFd;

fn get_ppid(pid: impl Display) -> anyhow::Result<u32> {
    Ok(fs::read_to_string(format!("/proc/{}/stat", pid))?
        .split_whitespace()
        .nth(3)
        .context("Failed to get ppid")?
        .parse::<u32>()?)
}

fn get_ppid_path() -> anyhow::Result<[u32; 16]> {
    let pid = unsafe { libc::getpid() } as u32;
    let mut parent_pid = unsafe { libc::getppid() } as u32;
    let mut pids = [0u32; 16];
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
    setup_metrics()?;

    let ppid_path = get_ppid_path()?;
    info!("Ignoring self pids: {:?}", ppid_path);

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove the limit on locked memory failed, ret is: {ret}");
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

    for syscall in ["vfs_write", "vfs_writev", "vfs_read", "vfs_readv"] {
        let program_name = format!("handle_{}", syscall);
        let program = ebpf.load_program::<FEntry>(&program_name)?;
        program.load(syscall, &btf)?;
        program.attach()?;
    }

    let program = ebpf.load_program::<FExit>("handle_filemap_fault")?;
    program.load("filemap_fault", &btf)?;
    program.attach()?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_ring = AsyncFd::new(ring_buf)?;
    let aggregator = Aggregator::new();

    loop {
        let mut guard = async_ring.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            let event = bytemuck::from_bytes::<FileAccessEvent>(&item);
            aggregator.process_event(event).await?;
        }

        guard.clear_ready();
    }
}

fn setup_metrics() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let builder = PrometheusBuilder::new();
    builder
        .idle_timeout(
            MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
            Some(Duration::from_secs(10)),
        )
        .install()
        .context("failed to install Prometheus recorder")?;
    
    metrics::describe_counter!("io_per_file", "I/O per file");
    

    Ok(())
}
