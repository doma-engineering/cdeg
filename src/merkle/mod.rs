use ring::rand::SystemRandom;
use ring::signature::{
    Ed25519KeyPair, KeyPair, Signature, ED25519, UnparsedPublicKey,
};
use sha2::{Digest, Sha256};
use roxmltree::{Document};
use std::error::Error;

/// Helper: Compute a SHA-256 hash of arbitrary data.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    hash_bytes
}

/// Build a list of leaves (hashes) from certain XML nodes.
/// In many scenarios, each **leaf** could be the entire text of a node or 
/// a node + its attributes. Here, for demo, we treat **each child node** of `<root>`
/// as a leaf for the Merkle tree. Adjust to your needs.
pub fn collect_leaves_from_xml(xml_str: &str) -> Result<Vec<[u8; 32]>, Box<dyn Error>> {
    let doc = Document::parse(xml_str)?;
    let root = doc
        .descendants()
        .find(|n| n.has_tag_name("root"))
        .ok_or("No <root> element found")?;

    let mut leaves = Vec::new();
    for child in root.children() {
        // We'll skip text nodes (whitespace, etc.) and only hash element nodes.
        if child.is_element() {
            let node_text = child.text().unwrap_or("");
            // For demonstration, let's just hash the node's tag + text:
            let leaf_data = format!("<{}>{}</{}>", child.tag_name().name(), node_text, child.tag_name().name());
            leaves.push(sha256_hash(leaf_data.as_bytes()));
        }
    }

    Ok(leaves)
}

/// Build a Merkle tree (in memory) from the leaf hashes.
/// Returns the final root hash (Vec<u8>) and a layered structure of the tree.
/// 
/// We'll do a simple approach:
///   - Pairwise hash leaves to get next level up
///   - If there's an odd number of nodes, duplicate the last one
///   - Continue until 1 root remains
/// 
/// We'll also keep track of the entire "levels" so we can later reconstruct proofs.
pub fn build_merkle_tree(leaves: &[ [u8; 32] ]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    let mut levels = Vec::new();

    // Start with the leaf level
    levels.push(leaves.to_vec());

    // Build upward until we have a single root
    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            // If we are at the last leaf and it's an odd count, duplicate
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                // Duplicate last
                current_level[i]
            };

            let combined = [left, right].concat();
            let parent_hash = sha256_hash(&combined);
            next_level.push(parent_hash);
            i += 2;
        }
        levels.push(next_level);
    }

    // The root is the single element in the last level
    let root_hash = *levels.last().unwrap().first().unwrap();
    (levels, root_hash)
}

/// Construct a proof (sibling hashes) for a leaf at index `leaf_index`.
/// We'll return the path as a vector of (sibling_hash, left_or_right).
///   - `left_or_right`: 
///        false = sibling is on the left
///        true  = sibling is on the right
/// This is needed so the verifier knows how to recombine them in order.
pub fn merkle_proof(
    levels: &Vec<Vec<[u8; 32]>>,
    leaf_index: usize,
) -> Vec<([u8; 32], bool)> {
    let mut proof = Vec::new();
    let mut index = leaf_index;

    // We skip the top root level, so go until levels.len()-1
    for level_idx in 0..(levels.len() - 1) {
        let level = &levels[level_idx];
        // Determine pair index
        let is_right_node = (index % 2) == 1;
        let pair_index = if is_right_node { index - 1 } else { index + 1 };

        // If pair_index is out of range (odd leaf count -> duplicated last),
        // it means it's the same as `index`.
        let sibling_index = if pair_index < level.len() {
            pair_index
        } else {
            index
        };

        let sibling_hash = level[sibling_index];
        proof.push((sibling_hash, !is_right_node));

        // Move up to the parent index
        index /= 2;
    }
    proof
}

/// Verify a Merkle proof, returning whether it reconstructs the `expected_root`.
/// 
/// - `leaf_hash`: the hash of the leaf we want to prove is in the tree
/// - `proof`: the sibling array plus left/right indicator
/// - `expected_root`: the known Merkle root hash
pub fn verify_merkle_proof(
    leaf_hash: [u8; 32],
    proof: &Vec<([u8; 32], bool)>,
    expected_root: [u8; 32],
) -> bool {
    let mut current_hash = leaf_hash;

    for (sibling_hash, sibling_is_right) in proof {
        // If sibling is right, then current_hash is left
        // If sibling is left, then current_hash is right
        let combined = if *sibling_is_right {
            // means: current_hash || sibling
            [current_hash, *sibling_hash].concat()
        } else {
            // means: sibling || current_hash
            [*sibling_hash, current_hash].concat()
        };
        current_hash = sha256_hash(&combined);
    }

    current_hash == expected_root
}

/// Sign the root hash with the notary's private key
pub fn sign_merkle_root(
    key_pair: &Ed25519KeyPair,
    merkle_root: &[u8],
) -> Signature {
    key_pair.sign(merkle_root)
}

/// Verify the signature on the root using the notary's public key
pub fn verify_merkle_root_signature(
    public_key: &[u8],
    merkle_root: &[u8],
    signature: &[u8],
) -> Result<(), ring::error::Unspecified> {
    let verifier = UnparsedPublicKey::new(&ED25519, public_key);
    verifier.verify(merkle_root, signature)
}

/// Find the leaf index for a node. For demonstration, suppose we do the same
/// logic that `collect_leaves_from_xml` did: each direct child of <root> is a leaf,
/// in the order encountered. We attempt to find the exact string of `node_str`.
/// In real usage, you'd want a more robust approach, e.g., using node IDs or
/// an actual DOM-based approach that ensures a unique matching.
pub fn find_leaf_index_for_node(xml_str: &str, node_str: &str) -> Result<usize, Box<dyn Error>> {
    let doc = Document::parse(xml_str)?;
    let root = doc
        .descendants()
        .find(|n| n.has_tag_name("root"))
        .ok_or("No <root> element found")?;

    let mut i = 0;
    for child in root.children() {
        if child.is_element() {
            // This is how we built the leaf's data in collect_leaves_from_xml:
            let node_text = child.text().unwrap_or("");
            let candidate = format!("<{}>{}</{}>", child.tag_name().name(), node_text, child.tag_name().name());
            if candidate == node_str {
                return Ok(i);
            }
            i += 1;
        }
    }
    Err("Node string not found among direct <root> children".into())
}

/// Minimal demonstration of building a Merkle tree, signing it, 
/// proving inclusion of a node <N>, and verifying.
pub fn main() -> Result<(), Box<dyn Error>> {
    // -------------------------------------------------------------------------
    // 1. We have an XML document
    // -------------------------------------------------------------------------
    let xml_doc = r#"
        <root>
            <N>Important Node</N>
            <Secret>Classified Data Here</Secret>
            <Other>Some more content</Other>
        </root>
    "#;

    // -------------------------------------------------------------------------
    // 2. Build Merkle tree from leaf-hashes of the XML
    //    (Here we treat each child of <root> as a leaf)
    // -------------------------------------------------------------------------
    let leaves = collect_leaves_from_xml(xml_doc)?;
    if leaves.is_empty() {
        println!("No leaves found. Exiting.");
        return Ok(());
    }

    let (levels, merkle_root) = build_merkle_tree(&leaves);

    // -------------------------------------------------------------------------
    // 3. Sign the Merkle root using notary's Ed25519 key
    // -------------------------------------------------------------------------
    let rng = SystemRandom::new();
    let key_pair_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?;
    let notary_key_pair = Ed25519KeyPair::from_pkcs8(key_pair_pkcs8.as_ref())?;

    let signature = sign_merkle_root(&notary_key_pair, &merkle_root);
    let public_key_bytes = notary_key_pair.public_key().as_ref();

    println!("Merkle Root: {:?}", hex::encode(merkle_root));
    println!("Signature on root: {:?}", hex::encode(signature.as_ref()));

    // -------------------------------------------------------------------------
    // 4. Suppose we want to prove that node N = "<N>Important Node</N>" is included.
    //    Let's find its leaf index, create the leaf hash, and build a Merkle proof.
    // -------------------------------------------------------------------------
    let node_n_str = "<N>Important Node</N>";
    let leaf_index = find_leaf_index_for_node(xml_doc, node_n_str)?;
    let leaf_hash_n = leaves[leaf_index];
    let proof_n = merkle_proof(&levels, leaf_index);

    // -------------------------------------------------------------------------
    // 5. Now we have:
    //    - `merkle_root` (signed by the notary)
    //    - `public_key_bytes` (the notary's public key)
    //    - `signature` on the root
    //    - For node <N>: the leaf hash, and the sibling path (proof_n)
    //
    //    We demonstrate how to verify:
    //      (a) The root signature is valid
    //      (b) The proof for leaf_hash_n indeed matches `merkle_root`
    // -------------------------------------------------------------------------

    // 5a. Verify the signature on the Merkle root
    match verify_merkle_root_signature(public_key_bytes, &merkle_root, signature.as_ref()) {
        Ok(_) => println!("Signature on Merkle root is valid."),
        Err(e) => {
            eprintln!("Invalid signature on Merkle root: {:?}", e);
            return Ok(());
        }
    }

    // 5b. Verify the Merkle path for <N>Important Node</N>
    let proof_valid = verify_merkle_proof(leaf_hash_n, &proof_n, merkle_root);

    if proof_valid {
        println!("SUCCESS: Merkle proof shows <N> is included in the signed document!");
    } else {
        println!("FAILURE: Merkle proof for <N> did NOT match the root.");
    }

    // -------------------------------------------------------------------------
    // 6. Analogously, to illustrate that the proofs are not malleable:
    // 
    //  (a) We'll build a leaf hash for a node that was NOT actually in the tree
    //      (since we only had <N>, <Secret>, and <Other> as leaves).
    //  (b) We shall also demonstrate that root node will be different!
    // -------------------------------------------------------------------------
    let node_m_str = "<M>Important Node</M>";
    let leaf_hash_m = sha256_hash(node_m_str.as_bytes());

    // We'll reuse the *same* Merkle proof (for <N>) as if it could "prove" <M>.
    let proof_m_valid = verify_merkle_proof(leaf_hash_m, &proof_n, merkle_root);

    if proof_m_valid {
        println!("FAILURE: We cheated and the Merkle proof was accepted for <M>!");
    } else {
        println!("SUCCESS: The Merkle proof is not valid for <M> (as expected)!");
    }

    // 6b. Build a hash for the new node <M>Important Node</M>.
    let mut tampered_leaves = leaves.clone();

    // find index for the old <N>:
    let node_n_str = "<N>Important Node</N>";
    let n_index = find_leaf_index_for_node(xml_doc, node_n_str)?;
    tampered_leaves[n_index] = leaf_hash_m; // Replace <N>'s leaf hash with <M>'s

    // 6b.1. Rebuild the Merkle tree from these tampered leaves
    let (_tampered_levels, tampered_merkle_root) = build_merkle_tree(&tampered_leaves);

    // 6c.2. Compare new tampered_merkle_root with the original merkle_root.
    if tampered_merkle_root == merkle_root {
        println!("FAILURE: The Merkle root did NOT change after replacing <N> with <M> (unexpected).");
    } else {
        println!(
            "SUCCESS: The Merkle root changed after replacing <N> with <M>.\n\
             Old root = {}\nNew root = {}",
            hex::encode(merkle_root),
            hex::encode(tampered_merkle_root)
        );
    }

    // 6e. The old signature was for merkle_root, not tampered_merkle_root.
    //     Attempting to verify the tampered root with the old signature must fail.
    match verify_merkle_root_signature(public_key_bytes, &tampered_merkle_root, signature.as_ref()) {
        Ok(_) => println!("FAILURE: The tampered root was accepted under the old signature (unexpected)!"),
        Err(e) => println!(
            "SUCCESS: The tampered root is NOT accepted by the old signature (as expected): Ring error {:?}",
            e
        ),
    }

    Ok(())
}
