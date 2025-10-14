
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

    let height = 4;

    let parent_test = MerkleAVC::get_parent_index_zero_padding(height, 14);
    println!("Parent index of 14: {:?}", parent_test);
    let parent_test = MerkleAVC::get_parent_index_zero_padding(height, 12);
    println!("Parent index of 12: {:?}", parent_test);
    let left_child_test = MerkleAVC::get_left_child_index_zero_padding(height, 14);
    println!("Left child index of 14: {:?}", left_child_test);
    let right_child_test = MerkleAVC::get_right_child_index_zero_padding(height, 14);
    println!("Right child index of 14: {:?}", right_child_test);
}
