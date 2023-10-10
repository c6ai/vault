## 1st-ZTA-of-HYOK-or-BYOK-KMI-with-Certified-HSM-based-DKE-for-Critical-DPI-v001.py
## 1st-ZTA-of-VSS(Verifiable-Secret-Sharing)-CoSi(Collective-Signing)-EdDSA-MultiSig-with-DKE-Vault-KMI.py
## 1st-ZTA-of-VSS-CoSi-EdDSA-MultiSig-with-DKE-Vault-KMI-v001.py

## Python code snippets to implement MultiSig with CoSi, such as described in the LinkedIn post:
## https://www.linkedin.com/feed/update/urn:li:activity:7117123168456056832?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A7117123168456056832%2C7117181356823977984%29&dashCommentUrn=urn%3Ali%3Afsd_comment%3A%287117181356823977984%2Curn%3Ali%3Aactivity%3A7117123168456056832%29
## (0) 1st-ENU-GBT+23-Scalable-Multi-domain-Trust-KMI-for-Segmented-NWs-2310-04898.pdf
## (GBT+23 [Grierson, Buchanan, Thomson, Ghaleb, Maglaras & Eckle @ IEEE CAMAD 2023 @ ENU BIL]
##  @ https://arxiv-vanity.com/papers/2310.04898 @ https://arxiv.org/abs/2310.04898 
## (1) https://datatracker.ietf.org/doc/draft-ford-cfrg-cosi
## (2) Azure Information Protection with HYOK (Hold Your Own Key). https://techcommunity.microsoft.com/t5/security-compliance-and-identity/azure-information-protection-with-hyok-hold-your-own-key/ba-p/249920.
## (3) Double Key Encryption overview and FAQ | Microsoft Learn. https://learn.microsoft.com/en-us/purview/double-key-encryption-overview
## (4) Announcing Thales HSM Backed Double Key Encryption for ... - Thales Group. https://cpl.thalesgroup.com/blog/encryption/microsoft-office-365-double-key-encyrption-with-luna-hsm.


# Refactored code for EdDSA multisig using ASM scheme
# Based on https://github.com/SwingbyProtocol/tss-lib

import tss
from tss import eddsa
from tss.utils import *

# Define the number of nodes (n) and the threshold (t) for each subgroup
n = 10
t = 6

# Generate the public parameters for the curve
curve = tss.CURVE_ED25519
g = curve.generator

# Each node generates its own secret share using VSS
shares = []
for i in range(n):
    # Generate a random polynomial of degree t-1
    poly = tss.Polynomial(t-1, curve)
    # Evaluate the polynomial at i+1 and set it as the secret share
    share = poly(i+1)
    # Compute the commitments for the polynomial coefficients
    commitments = [g * c for c in poly.coeffs]
    # Prove the validity of the share using a zero-knowledge proof
    proof = tss.PedersenVSS.prove(poly, i+1, g, commitments)
    # Store the share, the commitments and the proof
    shares.append((share, commitments, proof))

# Each node verifies the shares of other nodes using VSS
for i in range(n):
    # Get the share, the commitments and the proof of node i
    share_i, commitments_i, proof_i = shares[i]
    for j in range(n):
        if i != j:
            # Get the share of node j
            share_j = shares[j][0]
            # Verify that share_j is consistent with commitments_i and proof_i
            assert tss.PedersenVSS.verify(share_j, j+1, g, commitments_i, proof_i)

# Each node computes its own public key as the sum of all commitments
public_keys = []
for i in range(n):
    # Get the commitments of node i
    commitments_i = shares[i][1]
    # Sum up all commitments to get the public key
    public_key_i = sum(commitments_i, tss.ECPoint.infinity())
    # Store the public key
    public_keys.append(public_key_i)

# Each node chooses a random subset of nodes to form a subgroup
subgroups = []
for i in range(n):
    # Choose t random nodes (including itself) from n nodes
    subgroup_i = random.sample(range(n), t)
    # Store the subgroup
    subgroups.append(subgroup_i)

# Each node signs a transaction with its subgroup using a threshold scheme
signatures = []
for i in range(n):
    # Get the share and the subgroup of node i
    share_i = shares[i][0]
    subgroup_i = subgroups[i]
    # Generate a random nonce for signing
    nonce_i = tss.Polynomial.random(0, curve).coeffs[0]
    # Compute the nonce commitment as g * nonce_i
    commitment_i = g * nonce_i
    # Broadcast the commitment to the subgroup
    commitments = [None] * n
    commitments[i] = commitment_i
    for j in subgroup_i:
        if i != j:
            # Receive the commitment from node j
            commitment_j = g * shares[j][0].nonce
            commitments[j] = commitment_j
    # Compute the aggregated commitment as the sum of all commitments in the subgroup
    aggregated_commitment = sum(commitments[j] for j in subgroup_i)
    # Compute the challenge as H(aggregated_commitment || public_keys || message)
    challenge = tss.hash_to_scalar(aggregated_commitment, public_keys, message, curve)
    # Compute the partial signature as nonce_i + challenge * share_i
    partial_signature_i = nonce_i + challenge * share_i
    # Broadcast the partial signature to the subgroup
    partial_signatures = [None] * n
    partial_signatures[i] = partial_signature_i
    for j in subgroup_i:
        if i != j:
            # Receive the partial signature from node j
            partial_signature_j = shares[j][0].nonce + challenge * shares[j][0].value
            partial_signatures[j] = partial_signature_j
    # Compute the lagrange coefficients for the subgroup
    lagrange_coeffs = tss.lagrange_coeffs(subgroup_i, curve)
    # Compute the aggregated signature as the sum of lagrange_coeffs[j] * partial_signatures[j] for all j in the subgroup
    aggregated_signature_i = sum(lagrange_coeffs[j] * partial_signatures[j] for j in subgroup_i)
    # Store the aggregated signature and the aggregated commitment
    signatures.append((aggregated_signature_i, aggregated_commitment))

# Each node verifies the signatures of other nodes using ASM
for i in range(n):
    # Get the signature and the subgroup of node i
    signature_i, commitment_i = signatures[i]
    subgroup_i = subgroups[i]
    # Compute the challenge as H(commitment_i || public_keys || message)
    challenge_i = tss.hash_to_scalar(commitment_i, public_keys, message, curve)
    # Compute the expected public key as the sum of lagrange_coeffs[j] * public_keys[j] for all j in the subgroup
    expected_public_key_i = sum(tss.lagrange_coeffs(subgroup_i, curve)[j] * public_keys[j] for j in subgroup_i)
    # Verify that g * signature_i == commitment_i + challenge_i * expected_public_key_i
    assert g * signature_i == commitment_i + challenge_i * expected_public_key_i

# Each node outputs its own signature and subgroup
for i in range(n):
    print(f"Node {i+1} signed with subgroup {subgroups[i]} and signature {signatures[i]}")


##TODO: extend adopting the HVAC and Cryptography libraries to implement
## a PoC for HYOC HSM-based Double Key Encryption of MultiSig with CoSi

# Import the libraries
import hvac
import cryptography


# Initialize the HVAC client with the Vault URL and token
##TODO: after staging replace below token and URL at vault.example.com with a production vault.blockpass.org or vault.democracycounts.co.uk
client = hvac.Client(url='https://vault.c6ai.com', token='s.XXXXXXX')

# Generate a key pair for each authorized party using the Cryptography library
key_pairs = [cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate() for _ in range(5)]

# Encrypt a ballot using the HVAC library and the public key of the election authority
ballot = "Alice"
public_key = client.secrets.transit.read_key("election-authority")["data"]["keys"]["1"]["public_key"]
encrypted_ballot = client.secrets.transit.encrypt_data("election-authority", plaintext=ballot)

# # Sign the encrypted ballot using the private keys of each authorized party and aggregate them into a MultiSig signature using the Cryptography library
# signatures = [key_pair.sign(encrypted_ballot["data"]["ciphertext"].encode()) for key_pair in key_pairs]
# multisig_signature = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(b''.join(signatures))

# # Add the MultiSig signature to the encrypted ballot
# encrypted_ballot["data"]["signatures"] = multisig_signature

# # Encrypt the encrypted ballot again using the HVAC library and a second key stored in Microsoft Azure
# second_key = client.secrets.transit.read_key("azure-key")["data"]["keys"]["1"]["public_key"]
# double_encrypted_ballot = client.secrets.transit.encrypt_data("azure-key", plaintext=encrypted_ballot)

# # Count the ballot by decrypting it twice using the HVAC library and the private keys of the election authority and Microsoft Azure
# decrypted_ballot_1 = client.secrets.transit.decrypt_data("azure-key", ciphertext=double_encrypted_ballot["data"]["ciphertext"])
# decrypted_ballot_2 = client.secrets.transit.decrypt_data("election-authority", ciphertext=decrypted_ballot_1["data"]["plaintext"])
# vote_count = {"Alice": 1}

# # Sign the vote count using the private keys of each node in the network and aggregate them into a CoSi signature using the Cryptography library
# nodes = 10 # The number of nodes in the network
# node_key_pairs = [cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate() for _ in range(nodes)]
# node_signatures = [key_pair.sign(str(vote_count).encode()) for key_pair in node_key_pairs]
# cosi_signature = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(b''.join(node_signatures))

# # Add the CoSi signature to the vote count
# vote_count["cosi_signature"] = cosi_signature

# # Verify the election results by verifying the CoSi signature using the Cryptography library and the public keys of each node in the network
# node_public_keys = [key_pair.public_key() for key_pair in node_key_pairs]
# cosi.verify_signature(vote_count["cosi_signature"], str(vote_count).encode(), node_public_keys)

