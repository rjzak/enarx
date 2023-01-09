// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use der::Sequence;
use x509_cert::crl::CertificateList;

#[derive(Sequence)]
pub struct CrlPair<'a> {
    pub url: String,
    pub crl: CertificateList<'a>,
}

#[derive(Sequence)]
pub struct CachedCrl<'a> {
    pub crls: Vec<CrlPair<'a>>,
}

/// Fetch a URL and return the bytes
pub fn fetch_file(url: &str) -> anyhow::Result<Vec<u8>> {
    let mut reader = ureq::get(url)
        .call()
        .context(format!("retrieving CRL {url} from server"))?
        .into_reader();

    let mut bytes = vec![];
    reader
        .read_to_end(&mut bytes)
        .context("reading bytes buffer")?;

    Ok(bytes)
}
