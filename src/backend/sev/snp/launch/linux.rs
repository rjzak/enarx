// SPDX-License-Identifier: Apache-2.0

//! Types for interacting with the KVM SEV-SNP guest management API.
//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use super::super::{Error, Indeterminate};
use super::{Finish, Start, Update};

use crate::backend::sev::snp::launch::{IdAuth, IdBlock};
use iocuddle::{Group, Ioctl, WriteRead};
use std::marker::PhantomData;
use std::os::raw::c_ulong;
use std::os::unix::io::AsRawFd;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    Init2 = 22,
    LaunchStart = 100,
    LaunchUpdate<'_> = 101,
    LaunchFinish<'_> = 102,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the SEV-SNP platform in KVM.
pub const SEV_INIT2: Ioctl<WriteRead, &Command<'_, Init2>> = unsafe { ENC_OP.lie() };

/// Initialize the flow to launch a guest.
pub const SNP_LAUNCH_START: Ioctl<WriteRead, &Command<'_, LaunchStart>> = unsafe { ENC_OP.lie() };

/// Insert pages into the guest physical address space.
pub const SNP_LAUNCH_UPDATE: Ioctl<WriteRead, &Command<'_, LaunchUpdate<'_>>> =
    unsafe { ENC_OP.lie() };

/// Complete the guest launch flow.
pub const SNP_LAUNCH_FINISH: Ioctl<WriteRead, &Command<'_, LaunchFinish<'_>>> =
    unsafe { ENC_OP.lie() };

/// A generic SEV command
#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// create the command from a mutable subcommand
    pub fn from_mut(sev: &'a mut impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// create the command from a subcommand reference
    pub fn from(sev: &'a mut impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a `std::io::Error` in an `Indeterminate<Error>`
    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error),
        }
    }
}

/// Initialize the SEV-SNP platform in KVM.
#[derive(Default)]
#[repr(C, packed)]
pub struct Init2 {
    /// initial value of features field in VMSA
    vmsa_features: u64,
    /// Reserved space, must be always set to 0 when issuing the ioctl.
    flags: u32,
    /// maximum guest GHCB version allowed
    ghcb_version: u16,
    pad1: u16,
    pad2: [u32; 8],
}

impl Init2 {
    /// Create a new `Init` command
    pub fn new() -> Self {
        Self {
            vmsa_features: 0,
            flags: 0,
            ghcb_version: 2,
            pad1: 0,
            pad2: [0; 8],
        }
    }
}

/// Initialize the flow to launch a guest.
#[repr(C)]
pub struct LaunchStart {
    /// Guest policy. See Table 7 of the AMD SEV-SNP Firmware
    /// specification for a description of the guest policy structure.
    policy: u64,

    /// Hypervisor provided value to indicate guest OS visible workarounds.
    /// The format is hypervisor defined.
    gosvw: [u8; 16],

    flags: u16,

    pad0: [u8; 6],
    pad1: [u64; 4],
}

impl From<Start> for LaunchStart {
    fn from(start: Start) -> Self {
        Self {
            policy: start.policy,
            gosvw: start.gosvw,
            flags: 0,
            pad0: [0; 6],
            pad1: [0; 4],
        }
    }
}

/// Insert pages into the guest physical address space.
#[repr(C)]
pub struct LaunchUpdate<'a> {
    /// guest start frame number.
    start_gfn: u64,

    /// Userspace address of the page needed to be encrypted.
    uaddr: u64,

    /// Length of the page needed to be encrypted:
    /// (end encryption uaddr = uaddr + len).
    len: u64,

    /// Encoded page type. See Table 58 if the SNP Firmware specification.
    page_type: u8,

    pad0: u8,

    flags: u16,

    pad1: u32,
    pad2: [u64; 4],

    _phantom: PhantomData<&'a ()>,
}

impl LaunchUpdate<'_> {
    pub fn is_done(&self) -> bool {
        self.len == 0
    }
}

impl From<Update<'_>> for LaunchUpdate<'_> {
    fn from(update: Update<'_>) -> Self {
        Self {
            start_gfn: update.start_gfn,
            uaddr: update.uaddr.as_ptr() as _,
            len: update.uaddr.len() as _,
            page_type: update.page_type as _,
            pad0: 0,
            flags: 0,
            pad1: 0,
            pad2: [0; 4],
            _phantom: PhantomData,
        }
    }
}

pub const KVM_SEV_SNP_FINISH_DATA_SIZE: usize = 32;

/// Complete the guest launch flow.
#[repr(C)]
pub struct LaunchFinish<'a> {
    /// Userspace address of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_block_uaddr: u64,

    /// Userspace address of the authentication information of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_auth_uaddr: u64,

    /// Indicates that the ID block is present.
    id_block_en: u8,

    /// Indicates that the author key is present in the ID authentication information structure.
    /// Ignored if ID_BLOCK_EN is 0.
    auth_key_en: u8,

    vcek_disabled: u8,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this value.
    host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],

    pad: [u8; 3],

    flags: u16,

    pad1: [u64; 4],

    _phantom: PhantomData<&'a [u8]>,
}

impl From<Finish<'_, '_>> for LaunchFinish<'_> {
    fn from(finish: Finish<'_, '_>) -> Self {
        Self {
            id_block_uaddr: finish
                .id_block_n_auth
                .map(|(block, _)| block as *const IdBlock as u64)
                .unwrap_or(0),
            id_auth_uaddr: finish
                .id_block_n_auth
                .map(|(_, auth)| auth as *const IdAuth as u64)
                .unwrap_or(0),
            id_block_en: finish.id_block_n_auth.is_some().into(),
            auth_key_en: finish.auth_key_en.into(),
            vcek_disabled: u8::from(finish.vcek_disabled),
            host_data: finish.host_data,
            pad: [0u8; 3],
            flags: 0,
            pad1: [0; 4],
            _phantom: PhantomData,
        }
    }
}

/// SHA-384 of the Linux kernel VMSA, for an unmodified VCPU
///
/// The contents of the VMSA, which was used in `KVM_SNP_LAUNCH_FINISH` in the final launch update with page type VMSA.
///
/// # WARNING
/// This could change in any kernel version, but there is no other workaround at the moment.
///
/// A real fix would be a KVM_SNP_LAUNCH_FINISH_WITH_RESET_VECTOR ioctl, with a well-defined VMSA page contents.
pub const SEV_SNP_VMSA_SHA384: [u8; 48] = [
    0x64, 0x65, 0x7e, 0x8c, 0xbf, 0xcb, 0x82, 0x71, 0x16, 0xbf, 0x6e, 0x1b, 0x2d, 0xcc, 0x27, 0x49,
    0x18, 0xe6, 0xa2, 0x17, 0xb7, 0x59, 0x97, 0xdf, 0x16, 0x45, 0x52, 0x5e, 0x71, 0x59, 0x58, 0x13,
    0xf8, 0x99, 0x13, 0xc4, 0x60, 0x62, 0x1d, 0xb2, 0xa2, 0xa2, 0xe2, 0xbc, 0x91, 0x4d, 0x98, 0x5d,
];
