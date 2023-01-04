//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

#![allow(non_camel_case_types)]

use core::convert::TryFrom;
use p256::{
    EncodedPoint,
    ecdsa::{
        DerSignature,
        VerifyingKey as P256VerifyingKey,
        signature::DigestVerifier,
    },
};
use ::rsa::{
    BigUint,
    RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey},
};
use sha2::{Sha256, Digest as _};
use x509_cert::{
    certificate::Certificate,
    der::{
        Encode as _,
        referenced::OwnedToRef,
    },
};
use x509_parser::x509::X509Version;

// use super::constants::*;
use super::error::*;
use crate::attestation::{AttestationX509Extension, FidoGenCeAaguid};
use crate::proto::*;

use crate::internals::{tpm_device_attribute_parser, TpmVendor};

// Why OpenSSL over another rust crate?
// - The openssl crate allows us to reconstruct a public key from the
//   x/y group coords, where most others want a pkcs formatted structure. As
//   a result, it's easiest to use openssl as it gives us exactly what we need
//   for these operations, and despite it's many challenges as a library, it
//   has resources and investment into it's maintenance, so we can a least
//   assert a higher level of confidence in it that <backyard crypto here>.

// Object({Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]), Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]), Integer(-1): U64(1), Integer(1): U64(2), Integer(3): I64(-7)})
//

// Public key.
//
// Aggregates different types of public keys.
enum PublicKey {
    ES256(P256VerifyingKey),
    RS256(RsaVerifyingKey<Sha256>),
    INSECURE_RS1(&'static str),
}

impl TryFrom<(COSEAlgorithm, &Certificate)> for PublicKey {
    type Error = WebauthnError;

    fn try_from(
        (alg, cert): (COSEAlgorithm, &Certificate),
    ) -> Result<Self, Self::Error> {
        let pkey_info = cert.tbs_certificate.subject_public_key_info
            .owned_to_ref();
        match alg {
            COSEAlgorithm::ES256 => {
                P256VerifyingKey::try_from(pkey_info)
                    .map_err(|e| {
                        error!(?e, "ES256 public key from certificate");
                        WebauthnError::TransientError("ES256 public key from certificate")
                    })
                    .map(PublicKey::ES256)
            }
            COSEAlgorithm::RS256 => {
                RsaVerifyingKey::<Sha256>::try_from(pkey_info)
                    .map_err(|e| {
                        error!(?e, "RS256 public key from certificate");
                        WebauthnError::TransientError("RS256 public key from certificate")
                    })
                    .map(PublicKey::RS256)
            }
            COSEAlgorithm::INSECURE_RS1 => {
                Ok(PublicKey::INSECURE_RS1("INSECURE SHA1"))
            },
            _ => {
                error!(
                    "unsupported signature algorithm: {:?}",
                    cert.signature_algorithm.oid,
                );
                Err(WebauthnError::TransientError("unsupported signature algorithm"))
            }
        }
    }
}

impl TryFrom<&COSEKey> for PublicKey {
    type Error = WebauthnError;

    fn try_from(key: &COSEKey) -> Result<Self, Self::Error> {
        match &key.key {
            COSEKeyType::EC_EC2(ec2k) => {
                let encoded_point = EncodedPoint::from_affine_coordinates(
                    ec2k.x.as_ref().into(),
                    ec2k.y.as_ref().into(),
                    false,
                );
                let pkey = P256VerifyingKey::from_encoded_point(&encoded_point)
                    .map_err(|e| {
                        error!(?e, "ES256 public key from COSEKey");
                        WebauthnError::TransientError("ES256 public key from COSEKey")
                    })?;
                Ok(PublicKey::ES256(pkey))
            }
            COSEKeyType::RSA(rsak) => {
                let n = BigUint::from_bytes_be(rsak.n.as_ref());
                let e = BigUint::from_bytes_be(rsak.e.as_ref());
                let pkey = RsaPublicKey::new(n, e)
                    .map_err(|e| {
                        error!(?e, "RS256 public key from COSEKey");
                        WebauthnError::TransientError("RS256 public key from COSEKey")
                    })?;
                match key.type_ {
                    COSEAlgorithm::RS256 => {
                        let pkey = RsaVerifyingKey::<Sha256>::new(pkey);
                        Ok(PublicKey::RS256(pkey))
                    }
                    COSEAlgorithm::INSECURE_RS1 => {
                        Ok(PublicKey::INSECURE_RS1("INSECURE SHA1"))
                    }
                    // other RSA variants are not supported
                    COSEAlgorithm::RS384 |
                    COSEAlgorithm::RS512 |
                    COSEAlgorithm::PS256 |
                    COSEAlgorithm::PS384 |
                    COSEAlgorithm::PS512 => {
                        error!("unsupported RSA variant: {:?}", key.type_);
                        Err(WebauthnError::COSEKeyInvalidType)
                    }
                    _ => {
                        error!("unsupported COSE algorithm: {:?}", key.type_);
                        Err(WebauthnError::COSEKeyInvalidType)
                    }
                }
            }
            _ => {
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }
}

fn pkey_verify_signature(
    pkey: &PublicKey,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    match pkey {
        PublicKey::ES256(pkey) => {
            let signature = DerSignature::from_bytes(signature)
                .map_err(|e| {
                    error!(?e, "signature DER decoding");
                    WebauthnError::TransientError("signature DER decoding")
                })?;
            let mut digest = Sha256::new();
            digest.update(verification_data);
            let result = pkey.verify_digest(digest, &signature);
            Ok(result.is_ok())
        }
        PublicKey::RS256(pkey) => {
            let signature = RsaSignature::try_from(signature)
                .map_err(|e| {
                    error!(?e, "RS256 signature decoding");
                    WebauthnError::TransientError("RS256 signature decoding")
                })?;
            let mut digest = Sha256::new();
            digest.update(verification_data);
            let result = pkey.verify_digest(digest, &signature);
            Ok(result.is_ok())
        }
        PublicKey::INSECURE_RS1(_pkey) => {
            error!("INSECURE SHA1 USAGE DETECTED");
            Err(WebauthnError::CredentialInsecureCryptography)
        }
    }
}

pub(crate) fn verify_signature(
    alg: COSEAlgorithm,
    cert: &Certificate,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    let pkey = PublicKey::try_from((alg, cert))?;
    pkey_verify_signature(&pkey, signature, verification_data)
}

use x509_parser::prelude::{GeneralName, X509Error, X509Name};

fn check_extension<T, F>(
    extension: &Result<Option<T>, X509Error>,
    must_be_present: bool,
    f: F,
) -> WebauthnResult<()>
where
    F: Fn(&T) -> bool,
{
    match extension {
        Ok(Some(extension)) => {
            if f(extension) {
                Ok(())
            } else {
                trace!("Custome extension check failed");
                Err(WebauthnError::AttestationCertificateRequirementsNotMet)
            }
        }
        Ok(None) => {
            if must_be_present {
                trace!("Extension not present");
                Err(WebauthnError::AttestationCertificateRequirementsNotMet)
            } else {
                Ok(())
            }
        }
        Err(_) => {
            debug!("extension present multiple times or invalid");
            Err(WebauthnError::AttestationCertificateRequirementsNotMet)
        }
    }
}

pub struct TpmSanData<'a> {
    pub manufacturer: &'a str,
    pub model: &'a str,
    pub version: &'a str,
}

#[derive(Default)]
struct TpmSanDataBuilder<'a> {
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    version: Option<&'a str>,
}

impl<'a> TpmSanDataBuilder<'a> {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn manufacturer(mut self, value: &'a str) -> Self {
        self.manufacturer = Some(value);
        self
    }

    pub(crate) fn model(mut self, value: &'a str) -> Self {
        self.model = Some(value);
        self
    }

    pub(crate) fn version(mut self, value: &'a str) -> Self {
        self.version = Some(value);
        self
    }

    pub(crate) fn build(self) -> WebauthnResult<TpmSanData<'a>> {
        self.manufacturer
            .zip(self.model)
            .zip(self.version)
            .map(|((manufacturer, model), version)| TpmSanData {
                manufacturer,
                model,
                version,
            })
            .ok_or(WebauthnError::AttestationCertificateRequirementsNotMet)
    }
}

// pub(crate) const TCG_AT_TPM_MANUFACTURER: Oid = der_parser::oid!(2.23.133 .2 .1);
// pub(crate) const TCG_AT_TPM_MODEL: Oid = der_parser::oid!(2.23.133 .2 .2);
// pub(crate) const TCG_AT_TPM_VERSION: Oid = der_parser::oid!(2.23.133 .2 .3);

pub(crate) const TCG_AT_TPM_MANUFACTURER_RAW: &[u8] = &der_parser::oid!(raw 2.23.133 .2 .1);
pub(crate) const TCG_AT_TPM_MODEL_RAW: &[u8] = &der_parser::oid!(raw 2.23.133 .2 .2);
pub(crate) const TCG_AT_TPM_VERSION_RAW: &[u8] = &der_parser::oid!(raw 2.23.133 .2 .3);

impl<'a> TryFrom<&'a X509Name<'a>> for TpmSanData<'a> {
    type Error = WebauthnError;

    fn try_from(x509_name: &'a X509Name<'a>) -> Result<Self, Self::Error> {
        x509_name
            .iter_attributes()
            .try_fold(TpmSanDataBuilder::new(), |builder, attribute| {
                Ok(match attribute.attr_type().as_bytes() {
                    TCG_AT_TPM_MANUFACTURER_RAW => {
                        builder.manufacturer(attribute.attr_value().as_str()?)
                    }
                    TCG_AT_TPM_MODEL_RAW => builder.model(attribute.attr_value().as_str()?),
                    TCG_AT_TPM_VERSION_RAW => builder.version(attribute.attr_value().as_str()?),
                    _ => builder,
                })
            })
            .map_err(|_: der_parser::error::Error| WebauthnError::ParseNOMFailure)
            .and_then(TpmSanDataBuilder::build)
    }
}

pub(crate) fn assert_tpm_attest_req(x509: &Certificate) -> Result<(), WebauthnError> {
    let der_bytes = x509.to_der()
        .map_err(|e| {
            error!(?e, "certificate DER encoding");
            WebauthnError::TransientError("certificate DER encoding")
        })?;
    let x509_cert = x509_parser::parse_x509_certificate(&der_bytes)
        .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?
        .1;

    // TPM attestation certificate MUST have the following fields/extensions:

    // Version MUST be set to 3.
    if x509_cert.version != X509Version::V3 {
        return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
    }

    // Subject field MUST be set to empty.
    if x509.tbs_certificate.subject.0.len() != 0 {
        return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
    }

    // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
    // https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
    check_extension(
        &x509_cert.subject_alternative_name(),
        true,
        |subject_alternative_name| {
            // From [TPMv2-EK-Profile]:
            // In accordance with RFC 5280[11], this extension MUST be critical if
            // subject is empty and SHOULD be non-critical if subject is non-empty.
            //
            // We've already returned if the subject is non-empty, so we can just
            // check that the extension is critical.
            if !subject_alternative_name.critical {
                return false;
            };

            // The issuer MUST include TPM manufacturer, TPM part number and TPM
            // firmware version, using the directoryName form within the GeneralName
            // structure.
            subject_alternative_name
                .value
                .general_names
                .iter()
                .any(|general_name| {
                    if let GeneralName::DirectoryName(x509_name) = general_name {
                        TpmSanData::try_from(x509_name)
                            .and_then(|san_data| {
                                tpm_device_attribute_parser(san_data.manufacturer.as_bytes())
                                    .map_err(|_| WebauthnError::ParseNOMFailure)
                            })
                            .and_then(|(_, manufacturer_bytes)| {
                                TpmVendor::try_from(manufacturer_bytes)
                            })
                            .is_ok()
                    } else {
                        false
                    }
                })
        },
    )?;

    // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
    check_extension(
        &x509_cert.extended_key_usage(),
        true,
        |extended_key_usage| {
            extended_key_usage
                .value
                .other
                .contains(&der_parser::oid!(2.23.133 .8 .3))
        },
    )?;

    // The Basic Constraints extension MUST have the CA component set to false.
    check_extension(&x509_cert.basic_constraints(), true, |basic_constraints| {
        !basic_constraints.value.ca
    })?;

    // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution
    // Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is
    // available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].

    Ok(())
}

pub(crate) fn assert_packed_attest_req(pubk: &Certificate) -> Result<(), WebauthnError> {
    // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
    // Statement Certificate Requirements.
    // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
    let der_bytes = pubk.to_der()
        .map_err(|e| {
            error!("failed to encode certificate to DER: {}", e);
            WebauthnError::TransientError("failed to encode certificate to DER")
        })?;
    let x509_cert = x509_parser::parse_x509_certificate(&der_bytes)
        .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?
        .1;

    // The attestation certificate MUST have the following fields/extensions:
    // Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
    if x509_cert.version != X509Version::V3 {
        trace!("X509 Version != v3");
        return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
    }

    // Subject field MUST be set to:
    //
    // Subject-C
    //  ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
    // Subject-O
    //  Legal name of the Authenticator vendor (UTF8String)
    // Subject-OU
    //  Literal string “Authenticator Attestation” (UTF8String)
    // Subject-CN
    //  A UTF8String of the vendor’s choosing
    let subject = &x509_cert.subject;

    let subject_c = subject.iter_country().take(1).next();
    let subject_o = subject.iter_organization().take(1).next();
    let subject_ou = subject.iter_organizational_unit().take(1).next();
    let subject_cn = subject.iter_common_name().take(1).next();

    if subject_c.is_none() || subject_o.is_none() || subject_cn.is_none() {
        trace!("Invalid subject details");
        return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
    }

    match subject_ou {
        Some(ou) => match ou.attr_value().as_str() {
            Ok(ou_d) => {
                if ou_d != "Authenticator Attestation" {
                    trace!("ou != Authenticator Attestation");
                    return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
                }
            }
            Err(_) => {
                trace!("ou invalid");
                return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
            }
        },
        None => {
            trace!("ou not found");
            return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
        }
    }

    // If the related attestation root certificate is used for multiple authenticator models,
    // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
    // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
    //
    // We already check that the value matches the AAGUID in attestation
    // verification, so we only have to check the critical requirement here.
    //
    // The problem with this check, is that it's not actually required that this
    // oid be present at all ...
    check_extension(
        &x509_cert.get_extension_unique(&FidoGenCeAaguid::OID),
        false,
        |fido_gen_ce_aaguid| !fido_gen_ce_aaguid.critical,
    )?;

    // The Basic Constraints extension MUST have the CA component set to false.
    check_extension(&x509_cert.basic_constraints(), true, |basic_constraints| {
        !basic_constraints.value.ca
    })?;

    // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL
    // Distribution Point extension [RFC5280] are both OPTIONAL as the status of many
    // attestation certificates is available through authenticator metadata services. See, for
    // example, the FIDO Metadata Service [FIDOMetadataService].

    Ok(())
}

pub(crate) fn only_hash_from_type(
    alg: COSEAlgorithm,
    _input: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    match alg {
        COSEAlgorithm::INSECURE_RS1 => {
            // sha1
            warn!("INSECURE SHA1 USAGE DETECTED");
            Err(WebauthnError::CredentialInsecureCryptography)
        }
        c_alg => {
            debug!(?c_alg, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<&serde_cbor::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor::Value) -> Result<COSEKey, Self::Error> {
        let m = cbor_try_map!(d)?;

        // See also https://tools.ietf.org/html/rfc8152#section-3.1
        // These values look like:
        // Object({
        //     // negative (-) values are per-algo specific
        //     Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]),
        //     Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]),
        //     Integer(-1): U64(1),
        //     Integer(1): U64(2), // algorithm identifier
        //     Integer(3): I64(-7) // content type see https://tools.ietf.org/html/rfc8152#section-8.1 -7 being ES256 + SHA256
        // })
        // Now each of these integers has a specific meaning, and you need to parse them in order.
        // First, value 1 for the key type.

        let key_type_value = m
            .get(&serde_cbor::Value::Integer(1))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let key_type = cbor_try_i128!(key_type_value)?;

        let content_type_value = m
            .get(&serde_cbor::Value::Integer(3))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let content_type = cbor_try_i128!(content_type_value)?;

        let type_ = COSEAlgorithm::try_from(content_type)
            .map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?;

        // https://www.iana.org/assignments/cose/cose.xhtml
        // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
        // match key_type {
        // 1 => {} OctetKey
        if key_type == (COSEKeyTypeId::EC_EC2 as i128)
            && (type_ == COSEAlgorithm::ES256
                || type_ == COSEAlgorithm::ES384
                || type_ == COSEAlgorithm::ES512)
        {
            // This indicates this is an EC2 key consisting of crv, x, y, which are stored in
            // crv (-1), x (-2) and y (-3)
            // Get these values now ....

            let curve_type_value = m
                .get(&serde_cbor::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve_type = cbor_try_i128!(curve_type_value)?;

            let curve = ECDSACurve::try_from(curve_type)?;

            let x_value = m
                .get(&serde_cbor::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            let y_value = m
                .get(&serde_cbor::Value::Integer(-3))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let y = cbor_try_bytes!(y_value)?;

            let coord_len = curve.coordinate_size();
            if x.len() != coord_len || y.len() != coord_len {
                return Err(WebauthnError::COSEKeyECDSAXYInvalid);
            }

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve,
                    x: x.to_vec().into(),
                    y: y.to_vec().into(),
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_RSA as i128) && (type_ == COSEAlgorithm::RS256) {
            // RSAKey

            // -37 -> PS256
            // -257 -> RS256 aka RSASSA-PKCS1-v1_5 with SHA-256

            // -1 -> n 256 bytes
            // -2 -> e 3 bytes

            let n_value = m
                .get(&serde_cbor::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let n = cbor_try_bytes!(n_value)?;

            let e_value = m
                .get(&serde_cbor::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let e = cbor_try_bytes!(e_value)?;

            if n.len() != 256 || e.len() != 3 {
                return Err(WebauthnError::COSEKeyRSANEInvalid);
            }

            // Set the n and e, we know they are proper sizes.
            let mut e_temp = [0; 3];
            e_temp.copy_from_slice(e.as_slice());

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::RSA(COSERSAKey {
                    n: n.to_vec().into(),
                    e: e_temp,
                }),
            };

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_OKP as i128) && (type_ == COSEAlgorithm::EDDSA) {
            debug!(?d, "WebauthnError::COSEKeyInvalidType - EC_OKP");
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.2

            let curve_type_value = m
                .get(&serde_cbor::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve_type = cbor_try_i128!(curve_type_value)?;

            let x_value = m
                .get(&serde_cbor::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            if x.len() != 32 {
                return Err(WebauthnError::COSEKeyEDDSAXInvalid);
            }

            let mut x_temp = [0; 32];
            x_temp.copy_from_slice(x);

            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_OKP(COSEOKPKey {
                    curve: EDDSACurve::try_from(curve_type)?,
                    x: x_temp,
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else {
            debug!(?key_type, ?type_, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<(COSEAlgorithm, &Certificate)> for COSEKey {
    type Error = WebauthnError;
    fn try_from((alg, pubk): (COSEAlgorithm, &Certificate)) -> Result<COSEKey, Self::Error> {
        // common public key parameter extraction for p256, p384, and p521
        // generics may also work, though, type bounds will be too complicated
        macro_rules! extract_ec_key_x_y {
            ($curve:ident) => {
                {
                    // note that p521::ecdsa::VerifyingKey does not implement
                    // `From<SubjectPublicKeyInfo>`
                    use $curve::elliptic_curve::sec1::ToEncodedPoint as _;
                    let ec_key = $curve::PublicKey::try_from(
                        pubk.tbs_certificate.subject_public_key_info.owned_to_ref(),
                    ).map_err(|e| {
                        error!(?e, "extracting EC public key");
                        WebauthnError::TransientError("extracting EC public key")
                    })?;
                    let encoded_point = ec_key.to_encoded_point(false);
                    let x = encoded_point
                        .x()
                        .ok_or(WebauthnError::TransientError("elliptic curve x"))?
                        .to_vec();
                    let y = encoded_point
                        .y()
                        .ok_or(WebauthnError::TransientError("elliptic curve y"))?
                        .to_vec();
                    (x, y)
                }
            };
        }

        let key = match alg {
            COSEAlgorithm::ES256 => {
                let (x, y) = extract_ec_key_x_y!(p256);
                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: x.into(),
                    y: y.into(),
                }))
            }
            COSEAlgorithm::ES384 => {
                let (x, y) = extract_ec_key_x_y!(p384);
                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP384R1,
                    x: x.into(),
                    y: y.into(),
                }))
            }
            COSEAlgorithm::ES512 => {
                let (x, y) = extract_ec_key_x_y!(p521);
                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP521R1,
                    x: x.into(),
                    y: y.into(),
                }))
            }
            COSEAlgorithm::RS256
            | COSEAlgorithm::RS384
            | COSEAlgorithm::RS512
            | COSEAlgorithm::PS256
            | COSEAlgorithm::PS384
            | COSEAlgorithm::PS512
            | COSEAlgorithm::EDDSA
            | COSEAlgorithm::PinUvProtocol
            | COSEAlgorithm::INSECURE_RS1 => {
                error!(
                    "unsupported X509 to COSE conversion for COSE algorithm type {:?}",
                    alg
                );
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }?;

        Ok(COSEKey { type_: alg, key })
    }
}

impl COSEKey {
    pub(crate) fn get_alg_key_ecc_x962_raw(&self) -> Result<Vec<u8>, WebauthnError> {
        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        // Note: This signifies uncompressed ECC key format.
        match &self.key {
            COSEKeyType::EC_EC2(ecpk) => {
                let r: [u8; 1] = [0x04];
                Ok(r.iter()
                    .chain(ecpk.x.0.iter())
                    .chain(ecpk.y.0.iter())
                    .copied()
                    .collect())
            }
            _ => {
                debug!("get_alg_key_ecc_x962_raw");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => {
                macro_rules! validate_ec_key {
                    ($curve:ident) => {
                        {
                            let encoded_point =
                                $curve::EncodedPoint::from_affine_coordinates(
                                    ec2k.x.as_ref().into(),
                                    ec2k.y.as_ref().into(),
                                    false,
                                );
                            $curve::PublicKey::try_from(encoded_point)
                                .map_err(|e| {
                                    error!(?e, "validating EC public key");
                                    WebauthnError::TransientError("validating EC public key")
                                })?;
                            Ok(())
                        }
                    };
                }
                match ec2k.curve {
                    ECDSACurve::SECP256R1 => validate_ec_key!(p256),
                    ECDSACurve::SECP384R1 => validate_ec_key!(p384),
                    ECDSACurve::SECP521R1 => validate_ec_key!(p521),
                }
            }
            COSEKeyType::RSA(rsak) => {
                let n = BigUint::from_bytes_be(rsak.n.as_ref());
                let e = BigUint::from_bytes_be(rsak.e.as_ref());
                RsaPublicKey::new(n, e)
                    .map_err(|e| {
                        error!(?e, "verifying RSA public key");
                        WebauthnError::TransientError("verifying RSA public key")
                    })?;
                Ok(())
            }
            COSEKeyType::EC_OKP(_edk) => {
                warn!("ED25519 or ED448 keys are not currently supported");
                Err(WebauthnError::COSEKeyEDUnsupported)
            }
        }
    }

    pub(crate) fn verify_signature(
        &self,
        signature: &[u8],
        verification_data: &[u8],
    ) -> Result<bool, WebauthnError> {
        let pkey = PublicKey::try_from(self)?;
        pkey_verify_signature(&pkey, signature, verification_data)
    }
}

/// Compute the sha256 of a slice of data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(data);
    let mut output = [0u8; 32];
    digest.finalize_into((&mut output).into());
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use hex_literal::hex;
    use serde_cbor::Value;

    #[test]
    fn cbor_es256() {
        let hex_data = hex!(
            "
                A5         // Map - 5 elements
                01 02      //   1:   2,  ; kty: EC2 key type
                03 26      //   3:  -7,  ; alg: ES256 signature algorithm
                20 01      //  -1:   1,  ; crv: P-256 curve
                21 58 20   65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d // -2:   x,  ; x-coordinate
                22 58 20   1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c // -3:   y,  ; y-coordinate");

        let val: Value = serde_cbor::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES256);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP256R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es384() {
        let hex_data = hex!(
            "
                A5         // Map - 5 elements
                01 02      //   1:   2,  ; kty: EC2 key type
                03 38 22   //   3:  -35,  ; alg: ES384 signature algorithm
                20 02      //  -1:   2,  ; crv: P-384 curve
                21 58 30   ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69 // -2: x, ; x-coordinate
                           42c9cf891efe18ea81430517d777f5c43550da801be5bf2f
                22 58 30   dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd // -3: y ; y-coordinate
                           a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087 "
        );

        let val: Value = serde_cbor::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES384);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69
                         42c9cf891efe18ea81430517d777f5c43550da801be5bf2f"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd
                         a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP384R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es512() {
        let hex_data = hex!(
            "
                A5         // Map - 5 elements
                01 02      //   1:   2,  ; kty: EC2 key type
                03 38 23   //   3:  -36,  ; alg: ES512 signature algorithm
                20 03      //  -1:   3,  ; crv: P-521 curve
                21 58 42   0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd // -2:   x,  ; x-coordinate
                           b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72
                22 58 42   0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811 // -3:   y,  ; y-coordinate
                           b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536");

        let val: Value = serde_cbor::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES512);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd
                         b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811
                         b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP521R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }
}
