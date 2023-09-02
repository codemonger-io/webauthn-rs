// use base64urlsafedata::Base64UrlSafeData;

use crate::prelude::*;

use std::fmt;

pub struct Authority {
    pub ca: Certificate,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("subject", &self.ca.tbs_certificate.subject)
            .finish()
    }
}
