use crate::config::profile::{EncryptionOrder, EncryptionType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Hash,
    Sign,
    Encrypt,
}

pub fn order_of_operations(
    encrypt_type: Option<EncryptionType>,
    encrypt_order: Option<EncryptionOrder>,
    operations: &[Operation],
) -> Vec<Operation> {
    let mut ordered = Vec::new();

    let ets = match (encrypt_type, encrypt_order) {
        (Some(EncryptionType::Qbec), Some(EncryptionOrder::EncryptThenSign))
        | (Some(EncryptionType::Qbec), None) => true,
        (Some(EncryptionType::Qbec), Some(EncryptionOrder::SignThenEncrypt))
        | (Some(EncryptionType::Uie), _)
        | (Some(EncryptionType::None), _)
        | (None, _) => false,
    };

    if ets {
        if operations.contains(&Operation::Encrypt) {
            ordered.push(Operation::Encrypt);
        }
        if operations.contains(&Operation::Hash) {
            ordered.push(Operation::Hash);
        }
        if operations.contains(&Operation::Sign) {
            ordered.push(Operation::Sign);
        }
    } else {
        if operations.contains(&Operation::Hash) {
            ordered.push(Operation::Hash);
        }
        if operations.contains(&Operation::Sign) {
            ordered.push(Operation::Sign);
        }
        if operations.contains(&Operation::Encrypt) {
            ordered.push(Operation::Encrypt);
        }
    }

    ordered
}
