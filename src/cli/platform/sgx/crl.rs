// SPDX-License-Identifier: Apache-2.0

use super::super::caching::{fetch_file, CachedCrl, CrlPair};
use crate::backend::sgx::sgx_cache_dir;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Args;
#[allow(unused_imports)]
use der::{Decode, Encode};
use x509_cert::crl::CertificateList;
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

        let ca_crl_bytes = fetch_file(CERT_CRL).context(format!("fetching {CERT_CRL}"))?;
        let platform_crl_bytes =
            fetch_file(PLATFORM_CRL).context(format!("fetching {PLATFORM_CRL}"))?;
        let processor_crl_bytes =
            fetch_file(PROCESSOR_CRL).context(format!("fetching {PROCESSOR_CRL}"))?;

        let crl_list = CachedCrl {
            crls: vec![
                CrlPair {
                    url: CERT_CRL.to_string(),
                    crl: CertificateList::from_der(&ca_crl_bytes)?,
                },
                CrlPair {
                    url: PROCESSOR_CRL.to_string(),
                    crl: CertificateList::from_der(&processor_crl_bytes)?,
                },
                CrlPair {
                    url: PLATFORM_CRL.to_string(),
                    crl: CertificateList::from_der(&platform_crl_bytes)?,
                },
            ],
        };

        let crls = crl_list
            .to_vec()
            .context("converting Intel CRLs to DER encoding")?;

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
