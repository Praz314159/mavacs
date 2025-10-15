
use mavacs_plus::prelude::*;

fn main() {
    //let x = Serialize::serialize(&"Hello, world!").unwrap();
    //println!("{}", x.len());
    
    let cred: Credential = Credential::new(vec![
        AttributeValue::Integer(-12345),
        AttributeValue::UnsignedInteger(54321),
        AttributeValue::String("Prashanth".to_string()),
    ]);

    let byte_vector: Vec<Vec<u8>> = cred.to_byte_vector().unwrap();
    println!("Number of attributes: {}", byte_vector.len());
    for (i, bytes) in byte_vector.iter().enumerate() {
        println!("  Attribute {}: {} bytes", i, bytes.len());
    }

    let data = vec![
        vec![0u8; 32],
        vec![1u8; 32],
        vec![2u8; 32],
        vec![3u8; 32],
        vec![4u8; 32],
    ];

    let mvc:MerkleAVC = MerkleAVC::build_from_data(&data, PaddingScheme::Copy(vec![0u8]), TreeStorageType::StoredLeavesAndCalculatedHashes(vec![]));

}
