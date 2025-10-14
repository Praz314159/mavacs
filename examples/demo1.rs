use mavacs_plus::{MerkleSquare, Sha256Hasher};

fn main() {
    let mut msq: MerkleSquare<Sha256Hasher> = MerkleSquare::new(10);
    msq.append(b"a", b"1", b"sig").unwrap();
    msq.append(b"b", b"2", b"sig").unwrap();


    let mut msq2: MerkleSquare = MerkleSquare::new(10);
    for i in 0..13 {
        msq2.append(b"k", &[(i as u8)], b"s").unwrap();
    }
    let d = msq2.get_digest();
    println!("size: {}, roots: {}", d.size, d.roots.len());

    println!("{:#?}", msq2.roots[0])
}