# Log

## Entry 1 - 2025-10-05 - Attested Verifiable Anonymous Credential System Overview

### System Overview

A post-quantum anonymous credential system with three parties:
- **Issuer**: Creates and signs credentials containing attributes according to a published schema
- **Holder**: Receives credentials, later proves properties about them to verifiers
- **Verifier**: Checks proofs about credentials against policies

### Core Components

#### Schemas

An Issuer publishes a schema S of size l:
- **Schema S = (x₁, ..., xₗ)**: An ordered list of statements
- Each position i has an associated **relation Rᵢ**: A set of valid (statement, witness) pairs
- Each statement xᵢ ∈ L(Rᵢ), where L(Rᵢ) = {x | ∃w: Rᵢ(x,w) = 1}
- The schema declares what type of information belongs at each index

#### Attributes & Attribute Vectors

- **Attribute** ∈ U = {0,1}* ∪ {⊢}: Binary string or null value
- **Attribute vector**: attrs = (attr₁, ..., attrₗ) of length l matching schema
- **Well-formed attribute vector** (X*_{U|S}): Each attrᵢ satisfies Rᵢ(xᵢ, attrᵢ) = 1
  - Each attribute is a valid witness to its corresponding schema statement
- Label information is implicit in the index position

#### Policies

A Verifier's policy P = (x'₁, ..., x'ₙ) with n relationships:
- Each **relationship R'ᵢ** can involve multiple attributes (unlike schema relations)
- R'ᵢ(x'ᵢ, attrs_subset) = 1 where attrs_subset ⊆ full attribute vector
- **Trusting-intelligible**: ∃ well-formed attrs ∈ X*_{U|S} satisfying the policy
- **Distrusting-intelligible**: All satisfying attrs are well-formed

#### Verifiable Anonymous Credential (VAC)

A VAC contains:
1. **Attribute vector**: The actual credential data
2. **Validity witness**: Cryptographic proof the credential is in the Issuer's valid (non-revoked) set

The validity witness binds the attributes to the Issuer's public record, preventing:
- Use with different attributes
- Use of non-issued credentials
- Use of revoked credentials

### The Three Protocols

#### 1. ProveValid
- **Purpose**: Prove this credential was issued by the Issuer and is not revoked
- Interactive protocol that outputs 1 if credential belongs to Issuer's valid set, 0 otherwise
- Uses the validity witness against the Issuer's public record
- The witness itself binds the specific attribute vector to the Issuer's valid set

#### 2. Disclose
- **Purpose**: Selectively reveal specific attributes
- Reveals attrs_D ⊆ attrs (subset of attributes)
- Proves revealed attributes are at correct indices (matching schema labels)
- Attributes are revealed in plaintext

#### 3. ProveClaim
- **Purpose**: Prove attributes satisfy relationships without revealing them
- Proves relationships from policy (e.g., "Age ≥ 21")
- Zero-knowledge: doesn't reveal actual attribute values
- Can involve multiple attributes (e.g., "Age ≥ 21 AND State = 'CA'")

### Credential Validation Flow

To satisfy a Verifier's policy P:
1. **ProveValid**: Prove attrs is attested by Issuer (using validity witness)
2. **Disclose**: Provide disclosed attributes attrs_D
3. **Prove containment**: Prove attrs_D ⊆ attrs
4. **ProveClaim**: For each relationship in P, prove attrs satisfies it

Result: Verifier is convinced attrs satisfies P without learning unrevealed attributes

### Credential Issuance

Generalized negotiation protocol:
1. Holder selects some attributes (holder-chosen)
2. Holder reveals/proves these comply with schema
3. Issuer assigns remaining attributes (issuer-chosen)
4. Together they form a well-formed attribute vector ∈ X*_{U|S}
5. Issuer sends complete (or partial issuer-chosen) attribute vector to Holder

Special cases:
- Issuer assigns all attributes
- Holder chooses all attributes (self-attested credentials)

### Design Principles

- **Implementation agnostic**: Abstract over cryptographic backends, proof systems
- **Witness abstraction**: Support different validity witness schemes (Merkle trees, accumulators, etc.)
- **Protocol flexibility**: Support both interactive and non-interactive (Fiat-Shamir) variants
- **Attribute opacity**: Keep attributes untyped at this abstraction level

### Open Questions for Type System Design

1. What is a "statement" concretely? (Label, commitment, description?)
2. What does a relation Rᵢ look like in practice?
3. What parts of the schema are public vs private?
4. What does the validity witness prove membership of? (Attributes, commitment, identifier?)
5. How do ProveValid, Disclose, and ProveClaim proofs compose?
6. Do distrusting verifiers require explicit well-formedness proofs?
7. How should Statement, Relation, and Relationship be represented in Rust?

## Entry 2 - 2025-10-05 - Vector Commitment Trait Design

### Vector Commitment Primitive

A vector commitment is a cryptographic primitive that allows committing to a vector of values with the ability to prove and verify specific elements at specific indices without revealing the entire vector.

**Four Required Functions:**

1. **KeyGen(security_param, ...) → (public_params, key_material)**
   - Setup phase generating cryptographic parameters
   - Produces public parameters and secret key material for the committer

2. **Commit(vector, key) → commitment**
   - Takes a vector of values and secret key material
   - Outputs a compact commitment binding to the entire vector

3. **Open(index, commitment, vector, key) → proof**
   - Produces a proof that a specific value exists at a specific index
   - Requires the full vector and secret key material

4. **Verify(proof, commitment, value, index, params) → bool**
   - Verifies a proof that a claimed value exists at the claimed index
   - Returns true/false without requiring the full vector

**Properties:**
- **Binding**: Cannot produce valid proofs for different values at the same index
- **Succinctness**: Commitments and proofs should be compact
- **Position binding**: Proofs bind both value and position

### Associated Types vs Generics Decision

**Key Insight:** The difference between generics and associated types:
- **Generics** `trait Foo<T>`: Allow multiple implementations for the same type (one per `T`)
- **Associated types** `trait Foo { type T; }`: Allow only one implementation per type

**Example - Iterator uses associated type:**
```rust
trait Iterator {
    type Item;  // One logical answer to "what does this yield?"
}
```

**Decision: Use Associated Types**

Reasoning:
1. **Semantic clarity**: A vector commitment scheme commits to one specific type (attributes)
2. **Contained complexity**: Avoids spreading `<T>` type parameters throughout the codebase
3. **Cleaner signatures**: Functions need fewer type parameters
4. **Domain-specific**: We're committing to attribute vectors, not arbitrary data

**Cascade comparison:**
- With generics: `VerifiableAnonymousCredential<T, VC: VectorCommitment<T>>` everywhere
- With associated types: `VerifiableAnonymousCredential<VC: VectorCommitment>` - cleaner!

### Attribute Encoding Strategy

**Architecture Decision:**
- Attributes represented as `Vec<u8>` (byte arrays) at the cryptographic layer
- Issuer's schema defines how to encode/decode these bytes into typed data
- Use Rust's **Serde** ecosystem for serialization

**Workflow:**

1. **Issuer Side:**
   - Define schema with typed fields (age: u64, name: String, etc.)
   - Serialize each field to deterministic bytes using `bincode`
   - Commit to byte vector
   - Send to Holder: (commitment, signature, human-readable JSON)

2. **Holder Side:**
   - Receive human-readable JSON representation
   - Serialize back to bytes using same encoding
   - Verify reconstructed bytes match signed commitment

**Advantages:**
- Clean separation: crypto layer ↔ schema layer ↔ serialization layer
- VC implementations don't need to understand attribute semantics
- Easy to add new attribute types without touching crypto code
- Testable with simple byte vectors

**Serde Ecosystem:**
- `serde` - Core serialization framework
- `bincode` - Deterministic binary encoding (recommended)
- `serde_json` - Human-readable JSON encoding
- All support derive macros for automatic implementation

### Final Trait Design

```rust
pub trait VectorCommitment {
    type Element;
    type PublicParams;
    type KeyMaterial;
    type Commitment;
    type Proof;

    fn keygen(security_param: usize) -> (Self::PublicParams, Self::KeyMaterial);

    fn commit(vector: &[Self::Element], key: &Self::KeyMaterial) -> Self::Commitment;

    fn open(
        index: usize,
        commitment: &Self::Commitment,
        vector: &[Self::Element],
        key: &Self::KeyMaterial,
    ) -> Self::Proof;

    fn verify(
        proof: &Self::Proof,
        commitment: &Self::Commitment,
        value: &Self::Element,
        index: usize,
        params: &Self::PublicParams,
    ) -> bool;
}
```

**Usage for attributes:**
```rust
pub struct Attribute(Vec<u8>);

impl VectorCommitment for MerkleVC {
    type Element = Attribute;
    // ... other associated types
}
```

**No architectural problems anticipated** - associated types are the right choice for this use case.
