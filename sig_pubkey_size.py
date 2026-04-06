import math

def sig_and_pubkey_size(lam, q, m, n, r, k, z, t, w):
    """
    Computes the signature and public key size for a given security level
    
    Parameters:
    lam   : Security parameter (128, 192, 256)
    q     : Field size (2, 127)
    m, n  : Matrix dimensions (rows/cols)
    r     : Rank of secret matrix
    k     : Number of matrices in MinRank instance
    z     : Size of the multiplicative group E
    t     : Number of rounds repeated under Fiat-Shamir
    w     : Number of rounds with challenge b=1
    """
    
    # Precompute log_2(q) and weight of t when written in binary
    log2_q = math.log2(q)
    wt_t = bin(t).count('1')
            
    # Objective function components
    c0_c1_y_salt = 8 * lam
            
    # SeedTree + MerkleProof cost
    tree_inner = (t - w) * math.log2(t / (t - w)) + wt_t - 1
    seed_tree = 3 * lam * math.floor(tree_inner)
            
    # b=0 challenge (i not in I)
    resp_notin_I = (t - w) * (2 * lam + (m*n*log2_q + m*n*log2_z)
            
    # b=1 challenge (i in I)
    resp_in_I = w * (k * log2_q)
            
    # Total Size
    sig_size = c0_c1_y_salt + seed_tree + resp_notin_I + resp_in_I
    pubkey_size = lam + (m*n - k)*log2_q

    print(f"Signature Size = {sig_size / 8000:.2f} kB, Public Key Size = {pubkey_size / 8:.2f} B")


# ==========================================

sig_and_pubkey_size(lam=256, q=127, m=10, n=10, r=5, k=9, z=7, t=152, w=108)
