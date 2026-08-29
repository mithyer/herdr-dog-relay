//! Transient production certificate issuance from protected device material.
//!
//! The issuer reads the device Intermediate CA key only for one bounded request, verifies the CSR
//! signature and App identity, signs a short-lived leaf, and drops all private bytes before return.

use crate::{
    config::SecurityConfig,
    enrollment::{AppId, CertificateMetadata, CsrMetadata, EnrollmentError, Fingerprint},
    material::{
        MAX_PRIVATE_MATERIAL_BYTES, MAX_PUBLIC_MATERIAL_BYTES, ProtectedFileKind,
        read_protected_file,
    },
};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{Duration, OffsetDateTime};
use x509_parser::{certification_request::X509CertificationRequest, prelude::FromDer};

/// One public leaf chain plus non-secret metadata returned after issuance.
#[derive(Clone)]
pub struct IssuedCertificate {
    /// DER leaf followed by the device Intermediate chain.
    certificate_chain: Vec<Vec<u8>>,
    /// Public leaf certificate fingerprint.
    fingerprint: Fingerprint,
    /// SHA-256 digest of the CSR SubjectPublicKeyInfo used as the identity.
    app_identity: [u8; 32],
    /// Bounded public serial derived from the leaf digest.
    serial: u64,
    /// Validity start epoch seconds.
    not_before_epoch_seconds: u64,
    /// Validity end epoch seconds.
    not_after_epoch_seconds: u64,
}

impl std::fmt::Debug for IssuedCertificate {
    /// Reports certificate shape and metadata without exposing DER bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedCertificate")
            .field("certificate_count", &self.certificate_chain.len())
            .field("certificate_bytes_present", &true)
            .field("fingerprint_present", &true)
            .field("serial", &self.serial)
            .field("not_after_epoch_seconds", &self.not_after_epoch_seconds)
            .finish()
    }
}

impl IssuedCertificate {
    /// Returns the public certificate chain without private material.
    pub fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.certificate_chain.clone()
    }

    /// Returns the public leaf fingerprint.
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Returns the public SubjectPublicKeyInfo identity digest.
    pub const fn app_identity(&self) -> [u8; 32] {
        self.app_identity
    }

    /// Returns the public certificate expiry.
    pub const fn not_after_epoch_seconds(&self) -> u64 {
        self.not_after_epoch_seconds
    }

    /// Returns the public certificate serial.
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the public certificate metadata for allowlist persistence.
    pub fn metadata(
        &self,
        app_id: AppId,
        allowlist_generation: u64,
    ) -> Result<CertificateMetadata, EnrollmentError> {
        CertificateMetadata::new(
            app_id,
            self.fingerprint,
            self.serial,
            allowlist_generation,
            self.not_before_epoch_seconds,
            self.not_after_epoch_seconds,
        )
    }
}

/// Issues one App-client certificate using the configured device Intermediate CA.
pub fn issue_certificate(
    config: &SecurityConfig,
    expected_uid: u32,
    app_id: AppId,
    csr_bytes: &[u8],
    allowlist_generation: u64,
) -> Result<IssuedCertificate, EnrollmentError> {
    issue_certificate_with_intermediate(
        config,
        expected_uid,
        app_id,
        csr_bytes,
        allowlist_generation,
        config.device_intermediate_certificate(),
        config.device_intermediate_private_key(),
    )
}

/// Issues one Core-enrollment certificate using the dedicated Intermediate CA.
///
/// Core bootstrap is a separate trust domain from normal App QRM. This function therefore never
/// reads the App-client Intermediate paths and returns only the public leaf/Intermediate chain.
pub fn issue_core_certificate(
    config: &SecurityConfig,
    expected_uid: u32,
    csr_bytes: &[u8],
) -> Result<IssuedCertificate, EnrollmentError> {
    let app_id = app_id_from_csr(csr_bytes)?;
    issue_certificate_with_intermediate(
        config,
        expected_uid,
        app_id,
        csr_bytes,
        1,
        config.core_enrollment_intermediate_certificate(),
        config.core_enrollment_intermediate_private_key(),
    )
}

/// Parse and verify the bounded CSR Common Name used as the Core/App identity label.
pub fn app_id_from_csr(csr_bytes: &[u8]) -> Result<AppId, EnrollmentError> {
    let (_, parsed_csr) =
        X509CertificationRequest::from_der(csr_bytes).map_err(|_| EnrollmentError::InvalidCsr)?;
    parsed_csr
        .verify_signature()
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    let common_name = parsed_csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok())
        .ok_or(EnrollmentError::CsrMismatch)?;
    AppId::new(common_name.to_owned())
}

/// Issue one bounded clientAuth leaf from a selected purpose-specific Intermediate CA.
fn issue_certificate_with_intermediate(
    config: &SecurityConfig,
    expected_uid: u32,
    app_id: AppId,
    csr_bytes: &[u8],
    allowlist_generation: u64,
    intermediate_certificate_path: &std::path::Path,
    intermediate_key_path: &std::path::Path,
) -> Result<IssuedCertificate, EnrollmentError> {
    let csr_metadata = CsrMetadata::from_bytes(app_id.clone(), csr_bytes)?;
    if allowlist_generation == 0 {
        return Err(EnrollmentError::InvalidGeneration);
    }
    let csr_der = CertificateSigningRequestDer::from(csr_bytes.to_vec());
    let (_, parsed_csr) =
        X509CertificationRequest::from_der(csr_bytes).map_err(|_| EnrollmentError::InvalidCsr)?;
    parsed_csr
        .verify_signature()
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    let common_name = parsed_csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok())
        .ok_or(EnrollmentError::CsrMismatch)?;
    if common_name != app_id.as_str() {
        return Err(EnrollmentError::CsrMismatch);
    }
    let app_identity: [u8; 32] =
        Sha256::digest(parsed_csr.certification_request_info.subject_pki.raw).into();
    if app_identity == [0; 32] {
        return Err(EnrollmentError::InvalidCsr);
    }

    let intermediate_certificate = read_protected_file(
        intermediate_certificate_path,
        expected_uid,
        ProtectedFileKind::Public,
        MAX_PUBLIC_MATERIAL_BYTES,
    )
    .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let intermediate_key = read_protected_file(
        intermediate_key_path,
        expected_uid,
        ProtectedFileKind::Private,
        MAX_PRIVATE_MATERIAL_BYTES,
    )
    .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let root_certificate = read_protected_file(
        config.public_root_certificate(),
        expected_uid,
        ProtectedFileKind::Public,
        MAX_PUBLIC_MATERIAL_BYTES,
    )
    .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let issuer_certificate = first_pem_certificate(&intermediate_certificate)?;
    let root_certificate = first_pem_certificate(&root_certificate)?;
    let (_, parsed_intermediate) = x509_parser::parse_x509_certificate(issuer_certificate.as_ref())
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let (_, parsed_root) = x509_parser::parse_x509_certificate(root_certificate.as_ref())
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    validate_device_intermediate_chain(&parsed_intermediate, &parsed_root)?;
    let issuer_key = KeyPair::from_pem(
        std::str::from_utf8(&intermediate_key).map_err(|_| EnrollmentError::InvalidMetadata)?,
    )
    .map_err(|_| EnrollmentError::InvalidMetadata)?;
    if issuer_key.public_key_raw()
        != parsed_intermediate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
    {
        return Err(EnrollmentError::InvalidMetadata);
    }
    let issuer = Issuer::from_ca_cert_der(&issuer_certificate, issuer_key)
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let request = CertificateSigningRequestParams::from_der(&csr_der)
        .map_err(|_| EnrollmentError::InvalidCsr)?;
    let public_key = request.public_key;
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name.remove(DnType::CommonName);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, app_id.as_str());
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now - Duration::minutes(1);
    leaf_params.not_after = now + Duration::days(90);
    let request = CertificateSigningRequestParams {
        params: leaf_params,
        public_key,
    };
    let certificate = request
        .signed_by(&issuer)
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let leaf = certificate.der().to_vec();
    let digest_bytes: [u8; 32] = Sha256::digest(&leaf).into();
    let fingerprint = Fingerprint::from_bytes(digest_bytes)?;
    let mut serial_bytes = [0_u8; 8];
    serial_bytes.copy_from_slice(&digest_bytes[..8]);
    let serial = u64::from_be_bytes(serial_bytes).max(1);
    let not_before_epoch_seconds = u64::try_from(request.params.not_before.unix_timestamp())
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    let not_after_epoch_seconds = u64::try_from(request.params.not_after.unix_timestamp())
        .map_err(|_| EnrollmentError::InvalidMetadata)?;
    if csr_metadata.byte_len() != csr_bytes.len() {
        return Err(EnrollmentError::InvalidMetadata);
    }
    Ok(IssuedCertificate {
        certificate_chain: vec![leaf, issuer_certificate.to_vec()],
        fingerprint,
        app_identity,
        serial,
        not_before_epoch_seconds,
        not_after_epoch_seconds,
    })
}

/// Validates the configured Root and device Intermediate CA chain before any App leaf is issued.
fn validate_device_intermediate_chain(
    intermediate: &x509_parser::certificate::X509Certificate<'_>,
    root: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), EnrollmentError> {
    let is_valid_ca = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate.validity().is_valid()
            && certificate
                .tbs_certificate
                .basic_constraints()
                .ok()
                .flatten()
                .is_some_and(|extension| extension.value.ca)
            && certificate
                .tbs_certificate
                .key_usage()
                .ok()
                .flatten()
                .is_some_and(|extension| extension.value.key_cert_sign())
    };
    if !is_valid_ca(intermediate)
        || !is_valid_ca(root)
        || intermediate.tbs_certificate.issuer != root.tbs_certificate.subject
        || intermediate
            .verify_signature(Some(root.public_key()))
            .is_err()
        || root.tbs_certificate.issuer != root.tbs_certificate.subject
        || root.verify_signature(Some(root.public_key())).is_err()
    {
        return Err(EnrollmentError::InvalidMetadata);
    }
    Ok(())
}

/// Extracts the first certificate from a bounded PEM chain.
fn first_pem_certificate(bytes: &[u8]) -> Result<CertificateDer<'static>, EnrollmentError> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(bytes))
        .next()
        .ok_or(EnrollmentError::InvalidMetadata)?
        .map_err(|_| EnrollmentError::InvalidMetadata)
}

/// Returns current epoch seconds for local certificate metadata and challenge expiry.
pub fn current_epoch_seconds() -> Result<u64, EnrollmentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EnrollmentError::InvalidMetadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // TEST:relay/src/pki.rs[tests::csr_identity_is_bound]
    #[test]
    fn csr_identity_is_bound() {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![]).expect("params");
        params.distinguished_name.push(DnType::CommonName, "app-a");
        let csr = params.serialize_request(&key).expect("csr");
        let app = AppId::new("app-a").expect("app");
        let metadata = CsrMetadata::from_bytes(app.clone(), csr.der()).expect("metadata");
        assert_eq!(metadata.app_id(), &app);
    }

    // TEST:relay/src/pki.rs[tests::protected_material_can_issue_leaf]
    #[test]
    fn protected_material_can_issue_leaf() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("herdr-dog-pki-{suffix}"));
        std::fs::create_dir(&directory).expect("directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let uid = std::fs::metadata(&directory).expect("metadata").uid();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params
            .distinguished_name
            .push(DnType::CommonName, "deployment-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root =
            CertifiedIssuer::self_signed(root_params, KeyPair::generate().expect("root key"))
                .expect("root");
        let intermediate_signing_key = KeyPair::generate().expect("intermediate key");
        let mut intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "device-intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let intermediate = intermediate_params
            .signed_by(&intermediate_signing_key, &root)
            .expect("intermediate");
        let intermediate_cert = directory.join("intermediate.pem");
        let intermediate_key_path = directory.join("intermediate.key");
        let root_cert = directory.join("root.pem");
        crate::material::write_protected_file(
            &intermediate_cert,
            uid,
            intermediate.pem().as_bytes(),
            ProtectedFileKind::Public,
            MAX_PUBLIC_MATERIAL_BYTES,
        )
        .expect("intermediate cert");
        crate::material::write_protected_file(
            &intermediate_key_path,
            uid,
            intermediate_signing_key.serialize_pem().as_bytes(),
            ProtectedFileKind::Private,
            MAX_PRIVATE_MATERIAL_BYTES,
        )
        .expect("intermediate key");
        crate::material::write_protected_file(
            &root_cert,
            uid,
            root.pem().as_bytes(),
            ProtectedFileKind::Public,
            MAX_PUBLIC_MATERIAL_BYTES,
        )
        .expect("root cert");
        let config = crate::config::RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport=18743\n[security]\nmode=\"verified\"\nserver_certificate=\"/tmp/server.pem\"\nserver_private_key=\"/tmp/server.key\"\ntrusted_client_ca=\"/tmp/client-ca.pem\"\ndevice_intermediate_certificate=\"{}\"\ndevice_intermediate_private_key=\"{}\"\npublic_root_certificate=\"{}\"\n[enrollment]\nenabled=false\nallowlist_path=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            intermediate_cert.display(),
            intermediate_key_path.display(),
            root_cert.display(),
            directory.join("allowlist.json").display(),
        ))
        .expect("config");
        let app_key = KeyPair::generate().expect("app key");
        let mut params = CertificateParams::new(vec![]).expect("params");
        params.distinguished_name.push(DnType::CommonName, "app-a");
        let csr = params.serialize_request(&app_key).expect("csr");
        let issued = issue_certificate(
            config.security(),
            uid,
            AppId::new("app-a").expect("app"),
            csr.der(),
            2,
        )
        .expect("issued");
        assert_eq!(issued.certificate_chain().len(), 2);

        // A different CA may be syntactically valid but must not authorize this device Intermediate.
        let mut unrelated_params =
            CertificateParams::new(Vec::<String>::new()).expect("unrelated root params");
        unrelated_params
            .distinguished_name
            .push(DnType::CommonName, "unrelated-root");
        unrelated_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        unrelated_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let unrelated_root = CertifiedIssuer::self_signed(
            unrelated_params,
            KeyPair::generate().expect("unrelated root key"),
        )
        .expect("unrelated root");
        crate::material::write_protected_file(
            &root_cert,
            uid,
            unrelated_root.pem().as_bytes(),
            ProtectedFileKind::Public,
            MAX_PUBLIC_MATERIAL_BYTES,
        )
        .expect("replace root");
        assert!(
            issue_certificate(
                config.security(),
                uid,
                AppId::new("app-a").expect("app"),
                csr.der(),
                2,
            )
            .is_err()
        );
        std::fs::remove_dir_all(directory).expect("cleanup");
    }
}
