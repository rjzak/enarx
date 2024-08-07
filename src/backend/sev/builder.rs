// SPDX-License-Identifier: Apache-2.0

use super::snp::firmware::Firmware;
use super::snp::launch::*;

use super::{set_memory_attributes, SnpKeepPersonality};
use crate::backend::kvm::builder::{kvm_new_vcpu, map_sallyports};
use crate::backend::kvm::mem::{Region, Slot};
use crate::backend::kvm::KVM_HC_MAP_GPA_RANGE;
use crate::backend::sev::config::Config;
use crate::backend::ByteSized;

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::{thread, time};

use crate::backend::sev::cpuid_page::import_from_kvm;
use anyhow::{anyhow, Context, Error};
use kvm_bindings::{kvm_enable_cap, KVM_CAP_EXIT_HYPERCALL};
use kvm_ioctls::Kvm;
use mmarinus::{perms, Map};
use primordial::Page;
use rand::{thread_rng, Rng};
use sallyport::elf::pf::kvm::SALLYPORT;
use sallyport::elf::pf::snp::{CPUID, SECRETS};
use shared::std::cpuid_page::CpuidPage;
use x86_64::VirtAddr;

const SEV_RETRIES: usize = 3;
const SEV_RETRY_SLEEP_MS: u64 = 500;

pub struct Builder {
    config: Config,
    kvm_fd: Kvm,
    launcher: Launcher<Started, Firmware>,
    regions: Vec<Region>,
    sallyports: Vec<Option<VirtAddr>>,
}

fn retry<O>(func: impl Fn() -> anyhow::Result<O>) -> anyhow::Result<O> {
    let mut retries = SEV_RETRIES;
    let mut rng = thread_rng();
    loop {
        match func() {
            Err(e) if retries > 0 => {
                retries -= 1;
                eprintln!(
                    "Error {:#?}.\nRetry {} of {}.",
                    e,
                    SEV_RETRIES - retries,
                    SEV_RETRIES
                );
                let millis =
                    time::Duration::from_millis(SEV_RETRY_SLEEP_MS + rng.gen::<u8>() as u64);
                thread::sleep(millis);
                continue;
            }
            Err(e) => {
                return Err(e);
            }
            Ok(o) => {
                return Ok(o);
            }
        }
    }
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(config: super::config::Config) -> anyhow::Result<Self> {
        let (kvm_fd, launcher) = retry(|| {
            // try to open /dev/sev and start the Launcher several times

            let kvm_fd = Kvm::new().context("Failed to open '/dev/kvm'")?;

            const KVM_X86_SNP_VM: u64 = 4;
            let vm_fd = kvm_fd
                .create_vm_with_type(KVM_X86_SNP_VM)
                .context("Failed to create a virtual machine")?;

            vm_fd
                .enable_cap(&kvm_enable_cap {
                    cap: KVM_CAP_EXIT_HYPERCALL,
                    flags: 0,
                    args: [1 << KVM_HC_MAP_GPA_RANGE, 0, 0, 0],
                    pad: [0; 64],
                })
                .context("Failed to enable hypercall exits")?;

            let sev = retry(|| Firmware::open().context("Failed to open '/dev/sev'"))?;
            // FIXME: use RESTRICTED_INJECTION when available
            let launcher = Launcher::new(vm_fd, sev).context("SNP Launcher init failed")?;

            Ok((kvm_fd, launcher))
        })?;

        let start = Start {
            policy: config.parameters.policy,
            ..Default::default()
        };

        let launcher = launcher.start(start).context("SNP Launcher start failed")?;

        Ok(Builder {
            config,
            kvm_fd,
            launcher,
            regions: Vec::new(),
            sallyports: Vec::new(),
        })
    }
}

impl super::super::Mapper for Builder {
    type Config = super::config::Config;
    type Output = Arc<dyn super::super::Keep>;

    fn map(
        &mut self,
        mut pages: Map<perms::ReadWrite>,
        to: usize,
        with: u32,
    ) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        if with & SALLYPORT != 0 {
            map_sallyports(
                &pages,
                self.config.sallyport_block_size,
                &mut self.sallyports,
            );
        }

        let slot = Slot::new(
            self.launcher.as_mut(),
            self.regions.len() as u32,
            &pages,
            to as u64,
            true,
        )?;

        set_memory_attributes(self.launcher.as_mut(), to as u64, pages.len() as u64, true)?;

        if with & CPUID != 0 {
            assert_eq!(pages.len(), Page::SIZE);
            let mut cpuid_page = CpuidPage::default();
            import_from_kvm(&mut cpuid_page, &mut self.kvm_fd)
                .context("Failed to create CPUID page")?;

            let guest_cpuid_page = pages.as_mut_ptr() as *mut CpuidPage;
            unsafe {
                guest_cpuid_page.write(cpuid_page);
            }

            let update = Update::new(to as u64 >> 12, &pages, PageType::Cpuid);

            if self.launcher.update_data(update).is_err() {
                // Just try again with the firmware corrected values
                self.launcher
                    .update_data(update)
                    .context("launcher.update_data for CPUID failed")?;
            }
        } else if with & SECRETS != 0 {
            assert_eq!(pages.len(), Page::SIZE);

            let update = Update::new(to as u64 >> 12, &pages, PageType::Secrets);

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data failed")?;
        } else {
            let update = Update::new(to as u64 >> 12, pages.as_ref(), PageType::Normal);

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data failed")?;
        };

        self.regions.push(Region::new(slot, pages));

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(builder: Builder) -> anyhow::Result<Self> {
        let Builder {
            mut config,
            mut kvm_fd,
            mut launcher,
            regions,
            sallyports,
        } = builder;

        let sallyport_block_size = config.sallyport_block_size;
        let signatures = config.signatures.take();

        let id_block;
        let id_auth;

        // If no LOAD segment were defined as sallyport blocks
        if sallyports.is_empty() {
            anyhow::bail!("No sallyport blocks defined!");
        }

        let vcpu_fd = kvm_new_vcpu(&mut kvm_fd, launcher.as_mut(), 0)?;

        let finish = if let Some(signatures) = signatures {
            let sig_blob = signatures.sev;

            id_auth = IdAuth::from_bytes(&sig_blob.id_auth)
                .ok_or_else(|| anyhow!("Invalid SEV signature IdAuth blob size."))?;
            id_block = IdBlock::from_bytes(&sig_blob.id_block)
                .ok_or_else(|| anyhow!("Invalid SEV signature IdBlock blob size."))?;

            Finish::new(Some((&id_block, &id_auth)), true, false, [0u8; 32])
        } else {
            Finish::new(None, false, false, [0u8; 32])
        };

        let (vm_fd, sev_fd) = launcher
            .finish(finish)
            .context("SNP Launcher finish failed")?;

        Ok(Arc::new(RwLock::new(super::Keep::<SnpKeepPersonality> {
            kvm_fd,
            vm_fd,
            num_cpus: 1,
            cpu_fds: vec![vcpu_fd],
            regions,
            sallyport_block_size,
            sallyports,
            personality: SnpKeepPersonality { _sev_fd: sev_fd },
        })))
    }
}
