use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::el_gamal::ElGamalComponents;
#[derive(Debug, Serialize, Deserialize)]
pub struct MockCertificate {
    pub certificate_data: CertificateData,
    pub signature: Vec<u8>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateData {
    pub data: Data,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    pub name: String,
    pub el_gamal_components: ElGamalComponents,
    pub encrypted_nonce: Vec<u8>,
    pub encrypted_client_sk: Vec<u8>,
    pub encrypted_subj_data: Vec<u8>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SubjData {
    pub share_count: usize,
    pub el_gamal_public_key: BigUint,
}