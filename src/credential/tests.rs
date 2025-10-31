use super::credential::*;

#[test]
fn test_credential_creation() {
    let cred = Credential::new(vec![
        AttributeValue::Integer(42),
        AttributeValue::String("test".to_string()),
    ]);

    assert_eq!(cred.len(), 2);
    assert!(!cred.is_empty());
}

#[test]
fn test_empty_credential() {
    let cred = Credential::new(vec![]);

    assert_eq!(cred.len(), 0);
    assert!(cred.is_empty());
}

#[test]
fn test_credential_get() {
    let cred = Credential::new(vec![
        AttributeValue::Integer(42),
        AttributeValue::UnsignedInteger(100),
        AttributeValue::String("hello".to_string()),
    ]);

    assert_eq!(cred.get(0), Some(&AttributeValue::Integer(42)));
    assert_eq!(cred.get(1), Some(&AttributeValue::UnsignedInteger(100)));
    assert_eq!(cred.get(2), Some(&AttributeValue::String("hello".to_string())));
    assert_eq!(cred.get(3), None);
}

#[test]
fn test_credential_serialization() {
    let cred = Credential::new(vec![
        AttributeValue::Integer(-12345),
        AttributeValue::UnsignedInteger(54321),
        AttributeValue::String("Hello, world!".to_string()),
    ]);

    let byte_vector = cred.to_byte_vector().unwrap();

    assert_eq!(byte_vector.len(), 3);
    assert_eq!(byte_vector[0].len(), 6); // Integer serialized size
    assert_eq!(byte_vector[1].len(), 6); // UnsignedInteger serialized size
    assert_eq!(byte_vector[2].len(), 25); // String serialized size
}

#[test]
fn test_serialization_deterministic() {
    let cred = Credential::new(vec![
        AttributeValue::Integer(123),
    ]);

    let bytes1 = cred.to_byte_vector().unwrap();
    let bytes2 = cred.to_byte_vector().unwrap();

    // Same credential should produce identical bytes
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_different_attribute_types() {
    let cred = Credential::new(vec![
        AttributeValue::Integer(-1),
        AttributeValue::Integer(0),
        AttributeValue::Integer(1),
        AttributeValue::UnsignedInteger(0),
        AttributeValue::UnsignedInteger(65535),
        AttributeValue::String("".to_string()),
        AttributeValue::String("a".to_string()),
    ]);

    let byte_vector = cred.to_byte_vector().unwrap();

    assert_eq!(byte_vector.len(), 7);
    // All should successfully serialize
    for bytes in byte_vector {
        assert!(!bytes.is_empty());
    }
}
