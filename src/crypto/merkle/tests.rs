use super::merkle::*;
use super::errors::TreeIndexError;
use sha3::{Digest, Sha3_256};

#[test]
fn test_parent_index_calculation_zero_padding() {
    let height = 4;

    // For height 4: root_index = 14
    // Parent of node 12 should be 14
    assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 12), Ok(14));

    // Parent of node 13 should be 14
    assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 13), Ok(14));

    // Parent of node 10 should be 13
    assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 10), Ok(13));

    // Parent of node 11 should be 13
    assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 11), Ok(13));


}

#[test]
fn test_parent_index_calculation_copy_padding() {
    assert_eq!(MerkleAVC::get_parent_index_copy_padding(2, 5, 0), Ok(6));

    assert_eq!(MerkleAVC::get_parent_index_copy_padding(5, 3, 5), Ok(8));

    assert_eq!(MerkleAVC::get_parent_index_copy_padding(7, 3, 5), Ok(9));
}

#[test]
fn test_root_index_copy_padding() {
    // Test cases for various numbers of attributes
    let test_cases = vec![
        (2, 2),
        (5, 10),  // 5 attributes -> root at 10th index
    ];

    for (num_attributes, expected_nodes) in test_cases {
        assert_eq!(
            MerkleAVC::root_index_copy_padding(num_attributes),
            expected_nodes,
            "Failed for {} attributes",
            num_attributes
        );
    }
}

#[test]
fn test_root_has_no_parent() {
    let height = 4;

    // Root index for height 3 is 14
    let result = MerkleAVC::get_parent_index_zero_padding(height, 14);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TreeIndexError::RootHasNoParent);
}

#[test]
fn test_parent_index_out_of_bounds() {
    let height = 4;

    // Index 15 is out of bounds (root is 14)
    let result = MerkleAVC::get_parent_index_zero_padding(height, 15);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
}

#[test]
fn test_left_child_index_calculation() {
    let height = 4;

    // Left child of root (14) should be 12
    assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 14), Ok(12));

    // Left child of node 13 should be 10
    assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 13), Ok(10));

    // Left child of node 12 should be 8
    assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 12), Ok(8));
}

#[test]
fn test_right_child_index_calculation() {
    let height = 4;

    // Right child of root (14) should be 13
    assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 14), Ok(13));

    // Right child of node 13 should be 11
    assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 13), Ok(11));

    // Right child of node 12 should be 9
    assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 12), Ok(9));
}

#[test]
fn test_leaf_has_no_children() {
    let height = 4;

    // For height 3: last leaf index = 7
    // Leaf nodes should have no children
    let left_result = MerkleAVC::get_left_child_index_zero_padding(height, 5);
    assert!(left_result.is_err());
    assert_eq!(left_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);

    let right_result = MerkleAVC::get_right_child_index_zero_padding(height, 5);
    assert!(right_result.is_err());
    assert_eq!(right_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);
}

#[test]
fn test_child_index_out_of_bounds() {
    let height = 4;

    // Index 15 is out of bounds (root is 14)
    let left_result = MerkleAVC::get_left_child_index_zero_padding(height, 15);
    assert!(left_result.is_err());
    assert_eq!(left_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);

    let right_result = MerkleAVC::get_right_child_index_zero_padding(height, 15);
    assert!(right_result.is_err());
    assert_eq!(right_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
}

#[test]
fn test_build_zero_padded_tree_basic() {
    // Build a tree with 3 attributes
    let data = vec![
        vec![1u8, 2u8],
        vec![3u8, 4u8],
        vec![5u8, 6u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Tree should have height 3 (ceil(log2(3)) = 2, so 4 leaves)
    assert_eq!(tree.height, 3);
    assert_eq!(tree.num_attributes, 3);
    assert!(!tree.root.is_empty());

    // Verify tree structure is StoredLeavesAndCalculatedHashes
    match tree.stored_values {
        TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
            // For height 3: root_index = 2^3 - 2 = 6
            // Should have 7 nodes (indices 0-6)
            assert_eq!(nodes.len(), 7);
        }
        _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
    }
}

    #[test]
fn test_build_copy_padded_tree_basic() {
    // Build a tree with 3 attributes
    let data = vec![
        vec![1u8, 2u8],
        vec![3u8, 4u8],
        vec![5u8, 6u8],
        vec![7u8, 8u8],
        vec![9u8, 10u8],
    ];

    let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

    // Tree should have height 3 (ceil(log2(3)) = 2, so 4 leaves)
    assert_eq!(tree.height, 4);
    assert_eq!(tree.num_attributes, 5);
    assert!(!tree.root.is_empty());

    // Verify tree structure is StoredLeavesAndCalculatedHashes
    match tree.stored_values {
        TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
            // For height 3: root_index = 2^3 - 2 = 6
            // Should have 7 nodes (indices 0-6)
            assert_eq!(nodes.len(), 11);
        }
        _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
    }
}

#[test]
fn test_build_zero_padded_tree_power_of_two() {
    // Build a tree with exactly 4 attributes (power of 2)
    let data = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Should have height 3
    assert_eq!(tree.height, 3);
    assert_eq!(tree.num_attributes, 4);
}

#[test]
fn test_build_zero_padded_tree_single_element() {
    let data = vec![vec![42u8]];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Single element should have height 1
    assert_eq!(tree.height, 1);
    assert_eq!(tree.num_attributes, 1);

    // Root should be hash of the single element
    let mut hasher = Sha3_256::new();
    hasher.update(&[42u8]);
    let expected_root = hasher.finalize().to_vec();
    assert_eq!(tree.root, expected_root);
}

#[test]
fn test_generate_copath_first_leaf_zero_padding() {
    // Build a simple tree with 4 leaves
    let data = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Generate copath for first leaf (index 0)
    let copath = tree.generate_copath_for_zero_padded_full_tree(0).unwrap();

    // For height 3, copath should have length 2 (height - 1)
    assert_eq!(copath.len(), 2);

    // Each element should be a hash
    for hash in &copath {
        assert!(!hash.is_empty());
    }
}

#[test]
fn test_generate_copath_middle_leaf_zero_padding() {
    let data = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Generate copath for middle leaf (index 2)
    let copath = tree.generate_copath_for_zero_padded_full_tree(2).unwrap();

    assert_eq!(copath.len(), 2);
}

#[test]
fn test_generate_copath_out_of_bounds_zero_padding() {
    let data = vec![vec![1u8], vec![2u8]];
    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Try to generate copath for index beyond num_attributes
    let result = tree.generate_copath_for_zero_padded_full_tree(5);
    assert!(result.is_err(), "Should return error for out of bounds index");
}

#[test]
fn test_verify_copath_valid_zero_padding() {
    // Build a tree
    let data = vec![
        vec![10u8, 20u8],
        vec![30u8, 40u8],
        vec![50u8, 60u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    match tree.stored_values {
        TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
            // For height 3: root_index = 2^3 - 2 = 6
            println!("Tree nodes: {:#?}", nodes);
        },
        _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
    }

    // Generate copath for index 1
    let copath = tree.generate_copath_for_zero_padded_full_tree(1).unwrap();

    println!("Copath for index 1: {:#?}", copath);

    // Verify the copath with the correct value
    let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
        &copath,
        &tree.root,
        &data[1],
        1,
        tree.height,
    );

    assert!(is_valid, "Valid copath should verify successfully");
}

#[test]
fn test_verify_copath_invalid_value_zero_padding() {
    let data = vec![
        vec![10u8],
        vec![20u8],
        vec![30u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Generate copath for index 0
    let copath = tree.generate_copath_for_zero_padded_full_tree(0).unwrap();

    // Try to verify with wrong value
    let wrong_value = vec![99u8];
    let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
        &copath,
        &tree.root,
        &wrong_value,
        0,
        tree.height,
    );

    assert!(!is_valid, "Invalid value should fail verification");
}

#[test]
fn test_verify_copath_wrong_length_zero_padding() {
    let data = vec![vec![1u8], vec![2u8]];
    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Create copath with wrong length
    let wrong_copath = vec![vec![0u8; 32]]; // Wrong length for height 1 tree

    let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
        &wrong_copath,
        &tree.root,
        &vec![1u8],
        0,
        tree.height,
    );

    assert!(!is_valid, "Wrong copath length should fail verification");
}

#[test]
fn test_copath_roundtrip_all_leaves_zero_padding() {
    // Test that we can generate and verify copath for every leaf
    let data = vec![
        vec![100u8],
        vec![200u8],
        vec![50u8],
        vec![150u8],
        vec![250u8],
    ];

    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    // Verify copath for each leaf
    for (index, value) in data.iter().enumerate() {
        let copath = tree.generate_copath_for_zero_padded_full_tree(index as u16).unwrap();


        let is_valid: bool = MerkleAVC::verify_copath_for_zero_padded_full_tree(
            &copath,
            &tree.root,
            value,
            index as u16,
            tree.height,
        );

        assert!(is_valid, "Copath for leaf {} should verify", index);
    }
}

#[test]
fn test_verify_copath_wrong_root_zero_padding() {
    let data = vec![vec![1u8], vec![2u8]];
    let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

    let copath = tree.generate_copath_for_zero_padded_full_tree(0).unwrap();

    // Use wrong root
    let wrong_root = vec![0u8; 32];
    let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
        &copath,
        &wrong_root,
        &data[0],
        0,
        tree.height,
    );

    assert!(!is_valid, "Wrong root should fail verification");
}

#[test]
fn test_generate_copath_first_leaf_copy_padding() {
    // Build a tree with 5 leaves using copy padding
    let data = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
        vec![5u8],
    ];

    let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

    println!("Tree height: {}", tree.height);
    println!("Number of attributes: {}", tree.num_attributes);
    println!("Tree root: {:?}", tree.root);

    // Generate copath for first leaf (index 0)
    let copath = tree.generate_copath_for_copy_padded_full_tree(0).unwrap();

    // For height 4, copath should have length 3 (height - 1)
    assert_eq!(copath.len(), 3);

    // Each element should be a hash
    for hash in &copath {
        assert!(!hash.is_empty());
    }
}

#[test]
fn test_verify_copath_valid_copy_padding() {
    // Build a tree with copy padding
    let data = vec![
        vec![10u8, 20u8],
        vec![30u8, 40u8],
        vec![50u8, 60u8],
    ];

    let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

    match tree.stored_values {
        TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
            // For height 3: root_index = 2^3 - 2 = 6
            // Should have 7 nodes (indices 0-6)
            println!("Pretty-printed debug of points: {:#?}", nodes);
        }
        _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
    }


    // Generate copath for index 1
    let copath = tree.generate_copath_for_copy_padded_full_tree(1).unwrap();

    println!("Copath for index 1: {:#?}", copath);

    // Verify the copath with the correct value
    let is_valid = MerkleAVC::verify_copath_for_copy_padded_full_tree(
        &copath,
        &tree.root,
        &data[1],
        1,
        tree.num_attributes,
    );

    assert!(is_valid, "Valid copath should verify successfully");
}

#[test]
fn test_verify_copath_invalid_value_copy_padding() {
    let data = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
    ];

    let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

    // Generate copath for index 0
    let copath = tree.generate_copath_for_copy_padded_full_tree(0).unwrap();
    println!("test copath: {:#?}", copath);
    // Try to verify with wrong value
    let wrong_value = vec![5u8];
    println!("wrong value: {:?}", wrong_value);
    let is_valid = MerkleAVC::verify_copath_for_copy_padded_full_tree(
        &copath,
        &tree.root,
        &wrong_value,
        0,
        tree.num_attributes,
    );

    println!("is valid: {}", is_valid);

    assert!(!is_valid, "Invalid value should fail verification");
}

#[test]
fn test_copath_roundtrip_all_leaves_copy_padding() {
    // Test that we can generate and verify copath for every leaf with copy padding
    let data = vec![
        vec![100u8],
        vec![200u8],
        vec![50u8],
        vec![150u8],
        vec![250u8],
    ];

    let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

    match tree.stored_values {
        TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
            // For height 3: root_index = 2^3 - 2 = 6
            // Should have 7 nodes (indices 0-6)
            println!("Pretty-printed debug of points: {:#?}", nodes);
        }
        _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
    }

    // Verify copath for each leaf
    for (index, value) in data.iter().enumerate() {
        let copath = tree.generate_copath_for_copy_padded_full_tree(index as u16).unwrap();

        println!("index: {}", index);
        println!("copath: {:#?}", copath);

        let is_valid: bool = MerkleAVC::verify_copath_for_copy_padded_full_tree(
            &copath,
            &tree.root,
            value,
            index as u16,
            tree.num_attributes,
        );

        assert!(is_valid, "Copath for leaf {} should verify", index);
    }
}
