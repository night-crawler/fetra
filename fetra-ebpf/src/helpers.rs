// #[macro_export]
// macro_rules! r {
//     ($base:expr, $($field:tt).+) => {{
//         #[allow(unused_unsafe)]
//         unsafe { (*$base)$(.$field)+ }
//     }};
// }

#[macro_export]
macro_rules! container_of_mut {
    ($ptr:expr, $type:ty, $member:ident) => {{
        let offset = offset_of!($type, $member);
        let member_ptr = $ptr as *mut _ as *mut u8;
        let base_ptr = unsafe { member_ptr.offset(-(offset as isize)) };
        base_ptr as *mut $type
    }};
}

