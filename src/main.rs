use mavacs_plus::prelude::*;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Swap between workflows here - just comment/uncomment:
    run_vac_workflow();
    // run_cms_workflow();  // Uncomment when implementing Merkle Square
}

/// Vector Commitment (VAC) workflow - credential issuance and verification
fn run_vac_workflow() {
    println!("=== Running VAC Workflow ===\n");

    // 1. Create credential
    let cred = Credential::new(vec![
        AttributeValue::Integer(-12345),
        AttributeValue::UnsignedInteger(54321),
        AttributeValue::String("Prashanth".to_string()),
    ]);

    println!("Created credential: {}", cred);
    let byte_vector = cred.to_byte_vector().unwrap();
    println!("Serialized to {} byte vectors\n", byte_vector.len());

    // 2. Build commitments with different sizes and padding schemes
    for size in [10, 100, 1000] {
        println!("--- Testing with {} leaves ---", size);

        let data: Vec<Vec<u8>> = (0..size)
            .map(|i| vec![i as u8; 32])
            .collect();

        // Zero padding
        let tree_zero = MerkleAVC::build(
            &data,
            PaddingRule::Zero,
            TreeStorageType::Full(vec![])
        );
        println!("Built zero-padded tree: {}", tree_zero);

        // Copy padding
        let tree_copy = MerkleAVC::build(
            &data,
            PaddingRule::Copy,
            TreeStorageType::Full(vec![])
        );
        println!("Built copy-padded tree: {}", tree_copy);

        // 3. Generate and verify copaths (opening protocol)
        println!("Generating and verifying copaths...");
        for i in 0..10.min(size) {
            let copath = tree_zero.open(i).unwrap();
            let valid = MerkleAVC::verify(
                &copath,
                &tree_zero.root,
                &data[i as usize],
                i,
                PaddingRule::Zero,
                size as u16
            );
            if !valid {
                println!("❌ Verification failed for index {}", i);
            }
        }
        println!("✅ Verified 10 copaths\n");
    }

    println!("=== VAC Workflow Complete ===");
}

/// Credential Management System (CMS) workflow - Merkle Square operations
/// TODO: Implement when Merkle Square is ready
#[allow(dead_code)]
fn run_cms_workflow() {
    println!("=== Running CMS Workflow (Merkle Square) ===\n");

    // Future implementation:
    // - Build Merkle Square
    // - Row commitments
    // - Column commitments
    // - Batch proofs
    // - Non-membership proofs

    println!("⚠️  Not yet implemented");
}