#![no_std]
#![no_main]

use aya_ebpf::{macros::fentry, programs::FEntryContext};
use aya_log_ebpf::info;

#[fentry(function = "try_to_wake_up")]
pub fn fetra(ctx: FEntryContext) -> u32 {
    match try_fetra(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fetra(ctx: FEntryContext) -> Result<u32, u32> {
    info!(&ctx, "function try_to_wake_up called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
