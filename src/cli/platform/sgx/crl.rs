// SPDX-License-Identifier: Apache-2.0

use super::super::caching::fetch_crl_list;
use crate::backend::sgx::sgx_cache_dir;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Args;
#[allow(unused_imports)]
use x509_cert::der::Decode as _; // required for Musl target
#[allow(unused_imports)]
use x509_cert::der::Encode as _; // required for Musl target

const CERT_CRL: &str = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
const PROCESSOR_CRL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der";
const PLATFORM_CRL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der";

/// Fetch Intel's Certificate Revocation Lists (CRLs),
/// saving as cached files in `/var/cache/intel-sgx/` directory
#[derive(Args, Debug)]
pub struct CrlCache {}

impl CrlCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let mut dest_file = sgx_cache_dir()?;
        dest_file.push("crls.der");

        let crls = fetch_crl_list([CERT_CRL.into(), PROCESSOR_CRL.into(), PLATFORM_CRL.into()])?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_file)
            .context(format!(
                "opening destination file {dest_file:?} for saving Intel CRLs"
            ))?
            .write_all(&crls)
            .context(format!("writing Intel CRLs to file {dest_file:?}"))?;

        Ok(ExitCode::SUCCESS)
    }
}
