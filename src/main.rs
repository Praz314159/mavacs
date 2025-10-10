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

    let test_merkle_tree = merkle_vc::MerkleAVC {
        root: vec![],
        height: 3,
        num_attributes: 5,
        padding_scheme: merkle_vc::PaddingScheme::Zero,
        stored_values: merkle_vc::TreeStorageType::StoredLeaves(vec![]),
    };

    let parent_test = test_merkle_tree.get_parent_index_for_full_mavc_with_zero_padding(14);
    println!("Parent index of 14: {:?}", parent_test);
    let parent_test = test_merkle_tree.get_parent_index_for_full_mavc_with_zero_padding(12);
    println!("Parent index of 12: {:?}", parent_test);
    let left_child_test = test_merkle_tree.get_left_child_index_for_full_mavc_with_zero_padding(14);
    println!("Left child index of 14: {:?}", left_child_test);
    let right_child_test = test_merkle_tree.get_right_child_index_for_full_mavc_with_zero_padding(14);
    println!("Right child index of 14: {:?}", right_child_test);

    //let mvc:MerkleAVC = MerkleAVC::commit(byte_vector.as_slice(), &());

}
