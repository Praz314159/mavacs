mod credential;
mod vector_commitment;
mod merkle_vc;

use credential::{Credential, AttributeValue};
//use sha3::{Digest, Sha3_256};

fn main() {
    //let x = Serialize::serialize(&"Hello, world!").unwrap();
    //println!("{}", x.len());
    
    let cred: Credential = Credential::new(vec![
        AttributeValue::Integer(-12345),
        AttributeValue::UnsignedInteger(54321),
        AttributeValue::String("Hello, world!".to_string()),
    ]);

    let byte_vector: Vec<Vec<u8>> = cred.to_byte_vector().unwrap();
    println!("Number of attributes: {}", byte_vector.len());
    for (i, bytes) in byte_vector.iter().enumerate() {
        println!("  Attribute {}: {} bytes", i, bytes.len());
    }

    //let mvc:MerkleAVC = MerkleAVC::commit(byte_vector.as_slice(), &());

}
