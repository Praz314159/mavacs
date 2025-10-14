AVACS Protocol Specifications
Complete algorithmic protocols from Ramakrishna thesis Chapters 2-4, in page order

Page 23-24: CMS.Setup
┌─────────────────────────────────────────┐
│ CMS.Setup(1^λ) → (V_I, V_E)            │
├─────────────────────────────────────────┤
│ Input:  Security parameter λ            │
│ Output: Internal state V_I (private)    │
│         External state V_E (public)     │
│ Type:   Randomized                      │
└─────────────────────────────────────────┘

Page 23-24: CMS.Issue
┌─────────────────────┐                    ┌─────────────────────┐
│      Holder H       │                    │      Issuer I       │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │  Interactive protocol to obtain          │
           │  credential over attribute vector        │
           │                                          │
           ├────────────── attrs ───────────────────>│
           │                                          │
           │                                          │
           │<────────────── VAC ─────────────────────┤
           │                                          │

Input:  (V_I, V_E, attrs)
Output: (V'_I, V'_E, VAC)
Type:   Interactive, randomized

Page 23-24: CMS.Revoke
┌─────────────────────────────────────────┐
│ CMS.Revoke(V_I, V_E, VAC) → (V'_I, V'_E)│
├─────────────────────────────────────────┤
│ Input:  Internal state V_I              │
│         External state V_E              │
│         Credential VAC to revoke        │
│ Output: Updated internal state V'_I     │
│         Updated external state V'_E     │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 23-24: CMS.Verify
┌─────────────────────────────────────────┐
│ CMS.Verify(V_E, VAC) → {0, 1}          │
├─────────────────────────────────────────┤
│ Input:  External state V_E              │
│         Credential VAC                  │
│ Output: 1 if valid (not revoked)        │
│         0 if revoked                    │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 31: NIZKoK.Setup
┌─────────────────────────────────────────┐
│ NIZKoK.Setup(1^λ) → (crs, vrs, τ)      │
├─────────────────────────────────────────┤
│ Input:  Security parameter λ            │
│ Output: Common reference string crs     │
│         Verification ref string vrs     │
│         Trapdoor τ                      │
│ Type:   Randomized                      │
└─────────────────────────────────────────┘

Page 31: NIZKoK.Prove
┌─────────────────────────────────────────┐
│ NIZKoK.Prove(x, w, crs) → π            │
├─────────────────────────────────────────┤
│ Input:  Statement x ∈ L                 │
│         Witness w                       │
│         Common reference string crs     │
│ Output: Proof π that x ∈ L              │
│ Type:   Randomized                      │
│                                         │
│ Proves: (x, w) ∈ R (relation holds)    │
└─────────────────────────────────────────┘

Page 31: NIZKoK.Verify
┌─────────────────────────────────────────┐
│ NIZKoK.Verify(vrs, x, π) → {0, 1}      │
├─────────────────────────────────────────┤
│ Input:  Verification ref string vrs     │
│         Statement x                     │
│         Proof π                         │
│ Output: 1 if proof accepted             │
│         0 otherwise                     │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 35-36: VAC.ProveValid
┌─────────────────────┐                    ┌─────────────────────┐
│      Holder H       │                    │     Verifier V      │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │  Generate proof π_valid that            │
           │  credential is in valid set             │
           │                                          │
           │  Relation:                              │
           │    R_valid = {wit | CMS.Verify(V_E, VAC) = 1}
           │                                          │
           │              π_valid                     │
           ├─────────────────────────────────────────>│
           │                                          │
           │                                          │  Verify proof
           │              result ∈ {0,1}              │
           │<─────────────────────────────────────────┤
           │                                          │

Input:  (wit, attrs, V_E)
Output: Verification result
Type:   Randomized interactive protocol

Page 36: VAC.Disclose
┌─────────────────────┐                    ┌─────────────────────┐
│      Holder H       │                    │     Verifier V      │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │              idx_D (indices)             │
           │<─────────────────────────────────────────┤
           │                                          │
           │  Generate proof π_attrs_D that:         │
           │    attr_j = attrs_{i_j} ∀j ∈ idx_D     │
           │                                          │
           │  Relation:                              │
           │    R_disclose = {wit | attr_j = attrs_{i_j} ∀j}
           │                                          │
           │        (attrs_D, π_attrs_D)              │
           ├─────────────────────────────────────────>│
           │                                          │
           │                                          │  Verify disclosed
           │              result ∈ {0,1}              │  attributes
           │<─────────────────────────────────────────┤
           │                                          │

Input:  (wit, attrs, idx_D, attrs_D)
Output: Verification result
Type:   Randomized interactive protocol

Page 36: VAC.ProveClaim
┌─────────────────────┐                    ┌─────────────────────┐
│      Holder H       │                    │     Verifier V      │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │              claim                       │
           │<─────────────────────────────────────────┤
           │                                          │
           │  Generate proof π_claim that            │
           │  attrs satisfies claim statement        │
           │                                          │
           │  Proves arbitrary NP relation           │
           │  on attribute vector                    │
           │                                          │
           │              π_claim                     │
           ├─────────────────────────────────────────>│
           │                                          │
           │                                          │  Verify claim
           │              result ∈ {0,1}              │
           │<─────────────────────────────────────────┤
           │                                          │

Input:  (wit, attrs, claim)
Output: Verification result
Type:   Randomized interactive protocol

Page 48-49: Signature.KeyGen
┌─────────────────────────────────────────┐
│ Sig.KeyGen(1^λ) → (pk, sk)             │
├─────────────────────────────────────────┤
│ Input:  Security parameter λ            │
│ Output: Public key pk                   │
│         Secret key sk                   │
│ Type:   Randomized                      │
└─────────────────────────────────────────┘

Page 48-49: Signature.Sign
┌─────────────────────────────────────────┐
│ Sig.Sign(sk, M) → sig                  │
├─────────────────────────────────────────┤
│ Input:  Secret key sk                   │
│         Message M ∈ {0,1}*              │
│ Output: Signature sig                   │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 48-49: Signature.Verify
┌─────────────────────────────────────────┐
│ Sig.Verify(pk, M, sig) → {0, 1}        │
├─────────────────────────────────────────┤
│ Input:  Public key pk                   │
│         Message M                       │
│         Signature sig                   │
│ Output: 1 if valid signature            │
│         0 otherwise                     │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 50: Commitment.KeyGen
┌─────────────────────────────────────────┐
│ Com.KeyGen(1^λ) → pp                   │
├─────────────────────────────────────────┤
│ Input:  Security parameter λ            │
│ Output: Public parameters pp            │
│ Type:   Randomized                      │
└─────────────────────────────────────────┘

Page 50: Commitment.Commit
┌─────────────────────────────────────────┐
│ Com.Commit(M, r) → (com, aux)          │
├─────────────────────────────────────────┤
│ Input:  Message M ∈ M_pp                │
│         Randomness r ∈ R_pp             │
│ Output: Commitment com ∈ C_pp           │
│         Auxiliary info aux              │
│ Type:   Randomized                      │
│                                         │
│ Defines: M_pp × R_pp → C_pp            │
└─────────────────────────────────────────┘

Page 50: Commitment.Open
┌─────────────────────────────────────────┐
│ Com.Open(com, M, r) → {0, 1}           │
├─────────────────────────────────────────┤
│ Input:  Commitment com                  │
│         Message M                       │
│         Randomness r                    │
│ Output: 1 if com well-formed to M       │
│         0 otherwise                     │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 69: AuthDataStructure.Build
┌─────────────────────────────────────────┐
│ AD.Build(D) → dig                      │
├─────────────────────────────────────────┤
│ Input:  Dataset D = (d_1, ..., d_n)    │
│         where D ∈ X^n                   │
│ Output: Digest dig ∈ Y                  │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 69: AuthDataStructure.Auth
┌─────────────────────────────────────────┐
│ AD.Auth(i, d, D) → wit_d_i             │
├─────────────────────────────────────────┤
│ Input:  Index i ∈ [1, n]                │
│         Element d ∈ X                   │
│         Dataset D ∈ X^n                 │
│ Output: Witness wit_d_i that d = d_i   │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 69: AuthDataStructure.Verify
┌─────────────────────────────────────────┐
│ AD.Verify(i, d, dig, wit_d_i) → {0, 1} │
├─────────────────────────────────────────┤
│ Input:  Index i                         │
│         Element d                       │
│         Digest dig                      │
│         Witness wit_d_i                 │
│ Output: 1 if valid witness              │
│         0 otherwise                     │
│ Type:   Deterministic                   │
└─────────────────────────────────────────┘

Page 74-75: MAcc.Acc / MVC.Commit
┌─────────────────────────────────────────┐
│ MAcc.Acc(D) → (MT, root_MT)            │
│           or                            │
│ MVC.Commit(D) → (MT, root_MT)          │
├─────────────────────────────────────────┤
│ Input:  Data D                          │
│ Output: Merkle tree MT                  │
│         Root hash root_MT               │
│ Type:   Deterministic                   │
│                                         │
│ Note: Uses publicly known hash H        │
└─────────────────────────────────────────┘

Page 74-75: MAcc.Auth / MVC.Open
┌─────────────────────────────────────────┐
│ {MAcc, MVC}.{Auth, Open}(MT, l, d*)    │
│                          → wit_d*       │
├─────────────────────────────────────────┤
│ Input:  Merkle tree MT                  │
│         Leaf index l                    │
│         Element d*                      │
│ Output: Membership witness wit_d*       │
│         (authentication path c_leaf)    │
│ Type:   Deterministic                   │
│                                         │
│ Witness: Copath from leaf to root       │
└─────────────────────────────────────────┘

Page 74-75: MAcc.Verify / MVC.Verify
┌─────────────────────────────────────────┐
│ {MAcc, MVC}.Verify(root, l, d*, wit)   │
│                            → {0, 1}     │
├─────────────────────────────────────────┤
│ Input:  Root hash root_MT               │
│         Leaf index l                    │
│         Element d*                      │
│         Witness wit_d*                  │
│ Output: 1 if d* ∈ D at index l          │
│         0 otherwise                     │
│ Type:   Deterministic                   │
│                                         │
│ Check: Recompute root from leaf         │
└─────────────────────────────────────────┘

Page 74-75: MAcc.Update
┌─────────────────────────────────────────┐
│ MAcc.Update(MT, I, (d_i)_{i∈I})        │
│             → (root', MT', update)      │
├─────────────────────────────────────────┤
│ Input:  Merkle tree MT                  │
│         Set of indices I                │
│         New values (d_i) for each i∈I   │
│ Output: New root root'_MT               │
│         New tree MT'                    │
│         Update info for witnesses       │
│ Type:   Deterministic                   │
│                                         │
│ Note: For deletion, d_i = canonical val │
└─────────────────────────────────────────┘

Page 74-75: MAcc.UpdateWit
┌─────────────────────────────────────────┐
│ MAcc.UpdateWit(wit_d*, update)         │
│                → wit'_d*                │
├─────────────────────────────────────────┤
│ Input:  Membership witness wit_d*       │
│         Update information              │
│ Output: Updated witness wit'_d*         │
│         (valid for D' after changes)    │
│ Type:   Deterministic                   │
│                                         │
│ Updates witness for un-deleted element  │
└─────────────────────────────────────────┘

Page 79: Merkle2.Insert
┌─────────────────────────────────────────────┐
│ Merkle2.Insert(CF, d*) → (dig'_CF, CF')    │
├─────────────────────────────────────────────┤
│ Input:  Current chronological forest CF    │
│         Element d* to insert               │
│ Output: New forest CF'                     │
│         New digest dig'_CF                 │
│ Type:   Deterministic                      │
│                                            │
│ Algorithm:                                 │
│ 1. Append H(d*) as MT_k with h=0          │
│ 2. While h_i = h_{i+1}:                   │
│      - Merge MT_i and MT_{i+1}            │
│      - Build PT for new internal node     │
│      - h'_i ← h_i + 1                     │
│ 3. Update digest                          │
│                                            │
│ Complexity: O(log|D|) merges worst case    │
│ Each merge builds new Patricia trie       │
└─────────────────────────────────────────────┘

Page 80: Merkle2.Auth
┌─────────────────────────────────────────────────────┐
│ Merkle2.Auth(dig_CF, j, pre_d*, d*)                 │
│              → (wit_d*, wit_¬d*, ⊥)                 │
├─────────────────────────────────────────────────────┤
│ Input:  Digest dig_CF                               │
│         Chronological index j                       │
│         Prefix pre_d*                               │
│         Element d*                                  │
│ Output: Membership witness wit_d*           OR      │
│         Non-membership witness wit_¬d*      OR      │
│         Abort symbol ⊥                              │
│ Type:   Deterministic                               │
│                                                     │
│ Algorithm:                                          │
│ 1. Find MT_j* ∈ CF containing leaf j               │
│ 2. For each ancestor u_{j*}^{[α,β]} in MT_j*:      │
│      - Get auth path in PT_{j*}^{[α,β]}            │
│        for prefix pre_d*                           │
│      - Recover PT root from auth path              │
│ 3. Get auth path for d* in MT_j*                   │
│ 4. Combine into witness:                           │
│      wit_d* = (CF auth path, PT auth paths)        │
│                                                     │
│ Witness size: O(log²|D|)                           │
│   - O(log|D|) for chronological auth path          │
│   - O(log²|D|) for PT auth paths (one per ancestor)│
└─────────────────────────────────────────────────────┘

Page 80-81: Merkle2.Verify
┌─────────────────────────────────────────┐
│ Merkle2.Verify(dig_CF, j, d*, wit)     │
│                → {0, 1}                 │
├─────────────────────────────────────────┤
│ Input:  Digest dig_CF                   │
│         Chronological index j           │
│         Element d*                      │
│         Witness wit (membership or non) │
│ Output: 1 if valid witness              │
│         0 otherwise                     │
│ Type:   Deterministic                   │
│                                         │
│ Verifies:                               │
│ 1. Chronological auth path valid        │
│ 2. All PT auth paths valid              │
│ 3. PT roots match CF internal nodes     │
└─────────────────────────────────────────┘

Page 80-81: Merkle2.HistAuth
┌─────────────────────────────────────────┐
│ Merkle2.HistAuth(dig_e, dig_{e+1})     │
│                  → wit_{e:e+1}          │
├─────────────────────────────────────────┤
│ Input:  Digest at epoch e               │
│         Digest at epoch e+1             │
│ Output: Historical consistency witness  │
│ Type:   Deterministic                   │
│                                         │
│ Generates proof that dig_{e+1}          │
│ extends dig_e (append-only property)    │
│                                         │
│ Witness contains hashes needed to       │
│ recompute new roots from old roots      │
│                                         │
│ Composition for distant epochs:         │
│   wit_{e:e'} = (wit_{e:e+1}, ...,      │
│                 wit_{e'-1:e'})          │
│                                         │
│ Size: O(log|D|) per epoch transition    │
└─────────────────────────────────────────┘

Page 80-81: Merkle2.HistCheck
┌─────────────────────────────────────────┐
│ Merkle2.HistCheck(dig_e, dig_{e+1},    │
│                   wit_{e:e+1})          │
│                   → {0, 1}              │
├─────────────────────────────────────────┤
│ Input:  Old digest dig_e                │
│         New digest dig_{e+1}            │
│         Historical witness wit_{e:e+1}  │
│ Output: 1 if extension valid            │
│         0 otherwise                     │
│ Type:   Deterministic                   │
│                                         │
│ Algorithm:                              │
│ 1. Check: size(dig_{e+1}) > size(dig_e)│
│ 2. Try to recompute roots of dig_{e+1} │
│    from roots of dig_e + wit_{e:e+1}   │
│ 3. Return success/failure               │
│                                         │
│ Used by: Auditors to verify             │
│          transparency log               │
└─────────────────────────────────────────┘

Page 83: MAVACS CMS.Setup (Figure 4.3)
┌─────────────────────────────────────────────────┐
│ CMS.Setup(1^λ)                                  │
├─────────────────────────────────────────────────┤
│ 1: for i ∈ ID                                   │
│ 2:   (pk_i, sk_i) ← Sig_H.KeyGen(1^λ)          │
│ 3: U ← ID                                       │
│ 4: (MT_I, root_MT_I) ← MAcc.Acc({pk_i}_{i∈ID}) │
│ 5: return (V_I = (U, MT_I), V_E = root_MT_I)   │
└─────────────────────────────────────────────────┘

Where:
  ID = [1, N]  (N = 2^h unique subject identities)
  U  = FIFO stack tracking unused key indices
  MT_I = Merkle tree accumulator for public keys
  
V_I (Internal): Stack U + Merkle tree MT_I
V_E (External): Root hash root_MT_I (published)

Page 83-84: MAVACS CMS.Issue (Figure 4.4)
┌─────────────────────┐                    ┌─────────────────────┐
│      Holder H       │                    │      Issuer I       │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │  1: attrs_subj ← X*_U|_S                │
           │     attrs_H                              │
           ├─────────────────────────────────────────>│  attrs_I ← X*_U|_S
           │                                          │
           │  2: attrs_subj = attrs_H ∪ attrs_I      │
           │                                          │
           │  3: (MT_subj, root_MT_subj) ←           │
           │       MVC.Commit(attrs_subj)            │
           │                                          │
           │                                          │  4: i ← U.pop()
           │                                          │  5: c_i ← MAcc.Auth(
           │                                          │       MT_I, i, pk_i)
           │                                          │  6: sig_subj ←
           │            (attrs_I, i, pk_i,            │       Sig_H.Sign(sk_i,
           │<─────────── sig_subj, c_i) ─────────────┤       root_MT_subj)
           │                                          │
           │  7: check_1 ← MAcc.Verify(              │
           │       root_MT_I, i, pk_i, c_i)          │
           │  8: check_2 ← Sig_H.Verify(             │
           │       sig_subj, root_MT_subj, pk_i)     │
           │  9: return check_1 ∧ check_2            │
           │                                          │

Result: VAC_subj = (attrs = attrs_subj, 
                    wit = (sig_subj, i, pk_i, c_i))

H verifies:
  1. Authentication path for issuer's public key is valid
  2. Signature on attribute commitment is valid

Page 84: MAVACS CMS.Revoke (Figure 4.5)
┌─────────────────────────────────────────────────┐
│ CMS.Revoke(V_I, V_E, i)                         │
├─────────────────────────────────────────────────┤
│ 1: U' ← U.push(i)                               │
│ 2: (pk'_i, sk'_i) ← Sig_H.KeyGen(1^λ)          │
│ 3: (pk_i, sk_i) ← (pk'_i, sk'_i)               │
│ 4: (MT'_I, root'_MT_I, update) ←               │
│      MAcc.Update(MT_I, i, pk'_i)               │
│ 5: return (V'_I = (U', MT'_I),                 │
│            V_E = root'_MT_I, update)            │
└─────────────────────────────────────────────────┘

Revocation process:
1. Mark index i as unused (push to stack)
2. Generate fresh keypair
3. Replace revoked public key at leaf i
4. Recompute Merkle tree
5. Publish new root + distribute update info

Note: Remaining valid holders must update their
      witnesses using the update information

Legend
Notation:
  ←     : assignment
  →     : return/output
  ∈     : element of
  ∪     : union
  ∧     : logical AND
  |_S   : restricted to schema S
  [α,β] : node range in tree
  ⊥     : abort/error symbol
  
Complexity:
  N     : number of credentials/subjects
  |D|   : dataset size
  λ     : security parameter
  h     : tree height