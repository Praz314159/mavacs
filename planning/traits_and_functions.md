AVACS Algorithm Specifications (Chapters 2-4)
Complete algorithmic functionality from Ramakrishna thesis, in page order

Page 23-24: CMS (Credential Management System)
Setup(1^λ) → (V_I, V_E)
- Randomized algorithm
- Input: security parameter λ
- Output: internal state V_I (private), external state V_E (public)

Issue_{I,H}(V_I, V_E, attrs) → (V'_I, V'_E, VAC)
- Interactive algorithm between Issuer and Holder
- Input: internal state, external state, attribute vector
- Output: updated internal state, updated external state, new VAC

Revoke(V_I, V_E, VAC) → (V'_I, V'_E)
- Deterministic algorithm
- Input: internal state, external state, credential to revoke
- Output: updated internal state, updated external state

Verify(V_E, VAC) → {0, 1}
- Deterministic algorithm
- Input: external state, credential
- Output: 1 if valid (not revoked), 0 otherwise

Page 31: NIZKoK (Non-Interactive Zero-Knowledge)
Setup(1^λ) → (crs, vrs, τ)
- Randomized algorithm
- Input: security parameter λ
- Output: common reference string, verification reference string, trapdoor

Prove(x, w, crs) → π
- Randomized algorithm
- Input: statement x ∈ L, witness w, common reference string
- Output: proof π that x ∈ L

Verify(vrs, x, π) → {0, 1}
- Deterministic algorithm
- Input: verification reference string, statement, proof
- Output: 1 if proof accepted, 0 otherwise

Page 35-36: VAC (Verifiable Anonymous Credential)
ProveValid_{H,V}(wit, attrs, V_E) → {0, 1}
- Randomized interactive protocol between Holder and Verifier
- Input: witness, attributes, external state
- Output: verification result (1 if proof accepted)
- Relation: R_valid = {wit | CMS.Verify(V_E, VAC) = 1}

Disclose_{H,V}(wit, attrs, idx_D, attrs_D) → {0, 1}
- Randomized interactive protocol between Holder and Verifier
- Input: witness, attributes, disclosure indices, disclosed attributes
- Output: verification result (1 if proof accepted)
- Proves: attr_j = attrs_{i_j} for all j ∈ [1,t]

ProveClaim_{H,V}(wit, attrs, claim) → {0, 1}
- Randomized interactive protocol between Holder and Verifier
- Input: witness, attributes, claim statement
- Output: verification result (1 if proof accepted)
- Proves: attrs satisfies arbitrary NP relation claim

Page 48-49: Signature Schemes (Generic Interface)
KeyGen(1^λ) → (pk, sk)
- Randomized algorithm
- Input: security parameter λ
- Output: public key, secret key

Sign(sk, M) → sig
- Deterministic algorithm
- Input: secret key, message M ∈ {0,1}*
- Output: signature

Verify(pk, M, sig) → {0, 1}
- Deterministic algorithm
- Input: public key, message, signature
- Output: 1 if valid signature, 0 otherwise

Page 50: Commitment Schemes
KeyGen(1^λ) → pp
- Randomized algorithm
- Input: security parameter λ
- Output: public parameters pp

Commit(M, r) → (com, aux)
- Randomized algorithm
- Input: message M from message space M_pp, randomness r from R_pp
- Output: commitment com ∈ C_pp, auxiliary information

Open(com, M, r) → {0, 1}
- Deterministic algorithm
- Input: commitment, message, randomness
- Output: 1 if com is well-formed commitment to M, 0 otherwise

Page 69: Authenticated Data Structure (Generic)
Build(D) → dig
- Input: dataset D = (d_1, ..., d_n) ∈ X^n
- Output: digest dig ∈ Y

Auth(i, d, D) → wit_d_i
- Input: index i ∈ [1,n], element d ∈ X, dataset D ∈ X^n
- Output: witness that d = d_i ∈ D

Verify(i, d, dig, wit_d_i) → {0, 1}
- Input: index, element, digest, witness
- Output: 1 if valid witness, 0 otherwise

Page 74-75: Merkle Accumulator / Vector Commitment
MAcc.Acc(D) or MVC.Commit(D) → (MT, root_MT)
- Input: data D
- Output: Merkle tree MT, root hash

{MAcc, MVC}.{Auth, Open}(MT, l_d*, d*) → wit_d*
- Input: Merkle tree, leaf index l_d*, element d*
- Output: membership witness (authentication path c_leaf)

{MAcc, MVC}.Verify(root_MT, l_d*, d*, wit_d*) → {0, 1}
- Input: root hash, leaf index, element, witness
- Output: 1 if valid, 0 otherwise

MAcc.Update(MT, I, (d_i)_{i∈I}) → (root'_MT, MT', update)
- Input: Merkle tree, set of indices I, new values
- Output: new root, new tree, update information for witnesses

MAcc.UpdateWit(wit_d*, update) → wit'_d*
- Input: membership witness for d*, update information
- Output: updated membership witness for d* ∈ D'

Page 79-81: Merkle² (Chronological Forest + Patricia Tries)
Merkle2.Insert(CF, d*) → (dig'_CF, CF')
- Input: current chronological forest, element d* to insert
- Output: new chronological forest, new digest
- Operation: add-right-merge-left with Patricia trie construction

Merkle2.Auth(dig_CF, j, pre_d*, d*) → (wit_d*, wit_¬d*, ⊥)
- Input: digest, chronological index j, prefix pre_d*, element d*
- Output: membership witness OR non-membership witness OR abort
- Witness includes: 
  * Authentication path in chronological tree
  * Authentication paths in all Patricia tries for ancestors

Merkle2.Verify(dig_CF, j, d*, wit) → {0, 1}
- Input: digest, chronological index, element, witness
- Output: 1 if valid, 0 otherwise

Merkle2.HistAuth(dig_e, dig_{e+1}) → wit_{e:e+1}
- Input: digest at epoch e, digest at epoch e+1
- Output: historical consistency witness
- Witness proves dig_{e+1} extends dig_e (append-only)

Merkle2.HistCheck(dig_e, dig_{e+1}, wit_{e:e+1}) → {0, 1}
- Input: old digest, new digest, historical consistency witness
- Output: 1 if new digest properly extends old digest, 0 otherwise
- Used by auditors to verify append-only property

Page 83-84: MAVACS CMS (Concrete Merkle Implementation)
CMS.Setup(1^λ):
1. for i ∈ ID:
     (pk_i, sk_i) ← Sig_H.KeyGen(1^λ)
2. U ← ID  // FIFO stack of unused key indices
3. (MT_I, root_MT_I) ← MAcc.Acc({pk_i}_{i∈ID})
4. return (V_I = (U, MT_I), V_E = root_MT_I)

CMS.Issue_{H,I}(V_I, V_E, attrs_subj):
// Holder side:
1. attrs_subj ← X*_U|_S  // Collaborative population
2. (MT_subj, root_MT_subj) ← MVC.Commit(attrs_subj)

// Issuer side:
3. i ← U.pop()  // Get unused key index
4. c_i ← MAcc.Auth(MT_I, i, pk_i)  // Auth path for pk_i
5. sig_subj ← Sig_H.Sign(sk_i, root_MT_subj)
6. Send (attrs_I, i, pk_i, sig_subj, c_i) to Holder

// Holder verification:
7. check_1 ← MAcc.Verify(root_MT_I, i, pk_i, c_i)
8. check_2 ← Sig_H.Verify(sig_subj, root_MT_subj, pk_i)
9. return check_1 ∧ check_2

// Resulting VAC:
VAC_subj = (attrs = attrs_subj, wit = (sig_subj, i, pk_i, c_i))

CMS.Revoke(V_I, V_E, i):
1. U' ← U.push(i)  // Mark as unused
2. (pk'_i, sk'_i) ← Sig_H.KeyGen(1^λ)  // Generate new keypair
3. (pk_i, sk_i) ← (pk'_i, sk'_i)  // Replace old keypair
4. (MT'_I, root'_MT_I, update) ← MAcc.Update(MT_I, i, pk'_i)
5. return (V'_I = (U', MT'_I), V_E = root'_MT_I, update)