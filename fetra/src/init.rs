use anyhow::Context;
use log::warn;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub(crate) fn set_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove the limit on locked memory failed, ret is: {ret}");
    }
}

pub(crate) fn setup_metrics() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let builder = PrometheusBuilder::new();
    builder
        .with_http_listener(SocketAddr::from(([0, 0, 0, 0], 8819)))
        .idle_timeout(MetricKindMask::COUNTER, Some(Duration::from_secs(10)))
        .install()
        .context("failed to install Prometheus recorder")?;

    metrics::describe_counter!("io", "I/O");

    Ok(())
}

#[derive(Debug)]
pub(crate) struct MachineInfo {
    pub(crate) id: Arc<str>,
    #[allow(dead_code)]
    pub(crate) ips: Arc<[IpAddr]>,
    pub(crate) string_ips: Arc<str>,
    pub(crate) hostname: Arc<str>,
}

impl MachineInfo {
    pub(crate) async fn new() -> Self {
        let ips = get_ip_addresses().await;
        let string_ips = ips.iter().map(|ip| format!("{ip}")).collect::<Vec<_>>();
        Self {
            id: Arc::from(get_machine_id().await),
            ips: Arc::from(ips),
            hostname: Arc::from(get_hostname()),
            string_ips: Arc::from(string_ips.join(",")),
        }
    }
}

fn get_hostname() -> String {
    match hostname::get() {
        Ok(h) => h.to_string_lossy().to_string(),
        Err(err) => {
            warn!("failed to get hostname: {err}");
            String::from("unknown")
        }
    }
}

async fn get_sock_addr() -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    let sock_addr = socket.local_addr()?;
    Ok(sock_addr.ip())
}

async fn get_ip_addresses() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(addrs) => {
            ips.extend(addrs.into_iter().map(|addr| addr.ip()));
        }
        Err(err) => {
            warn!("Failed to obtain socket addr: {err}");
        }
    }

    ips.retain(|ip| {
        if ip.is_loopback() {
            return false;
        }

        match ip {
            IpAddr::V4(addr)
                if addr.is_link_local()
                || addr.is_documentation()
                || addr.is_unspecified()
                // filter private addresses to drop docker stuff
                // and later get some local addr from polling google dns
                || addr.is_private() =>
            {
                return false;
            }
            IpAddr::V6(addr) if addr.is_unspecified() || addr.is_unique_local() => {
                return false;
            }
            _ => {}
        }

        true
    });

    match get_sock_addr().await {
        Ok(addr) => {
            ips.push(addr);
        }
        Err(err) => {
            warn!("Failed to obtain socket addr: {err} (internet)");
        }
    };

    ips.sort_unstable();
    ips.dedup();

    ips
}

async fn get_machine_id() -> String {
    match tokio::fs::read_to_string("/etc/machine-id").await {
        Ok(s) => s.trim().to_owned(),
        Err(err) => {
            warn!("Failed to read /etc/machine-id: {err}");
            "unknown".to_owned()
        }
    }
}
