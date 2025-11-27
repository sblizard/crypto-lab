from private_polling import (
    keyGen,
    submit_vote,
    tally_votes,
    encrypt,
    decrypt,
    generate_proof,
    verify_proof,
    add_two_ciphertexts,
)
from polling_types import ECCKeyPair, EncryptedVote
from typing import cast
from tinyec.ec import Point  # type: ignore


failed_tests = []


def error(s):
    print("=== ERROR: " + s)
    failed_tests.append(s)


print("=== Private Polling System Test ===\n")

print("Step 1: Generating keypair for the election")
keypair: ECCKeyPair = keyGen()
pk = cast(Point, keypair.public_key)
sk = keypair.private_key
print("- Keypair generated\n")

print("Step 2: Testing basic encryption/decryption")
test_message = 5
ct, r = encrypt(pk=pk, m=test_message)
decrypted = decrypt(sk=sk, c_sum=ct, num_votes=10)
if decrypted == test_message:
    print(f"- Encrypted {test_message}, decrypted {decrypted}\n")
else:
    error(f"Encryption/decryption failed. Expected {test_message}, got {decrypted}")

print("Step 3: Testing zero-knowledge proof generation and verification")
vote_value = 1
ct_vote, r = encrypt(pk=pk, m=vote_value)
proof = generate_proof(pk=pk, ct=ct_vote, m=vote_value, r=r)
is_valid = verify_proof(pk=pk, ct=ct_vote, proof=proof)
if is_valid:
    print("- Proof generated and verified successfully\n")
else:
    error("Proof verification failed")

print("Step 4: Testing vote submission")
vote1 = submit_vote(pk=pk, vote=1)  # Yes vote
vote2 = submit_vote(pk=pk, vote=0)  # No vote
vote3 = submit_vote(pk=pk, vote=1)  # Yes vote
print("- Three votes submitted (Yes, No, Yes)\n")

print("Step 5: Verifying individual votes")
valid1 = verify_proof(pk=pk, ct=vote1.ciphertext, proof=vote1.proof)
valid2 = verify_proof(pk=pk, ct=vote2.ciphertext, proof=vote2.proof)
valid3 = verify_proof(pk=pk, ct=vote3.ciphertext, proof=vote3.proof)
if valid1 and valid2 and valid3:
    print("- All individual vote proofs verified\n")
else:
    error("Some vote proofs failed verification")

print("Step 6: Testing vote tallying")
votes: list[EncryptedVote] = [vote1, vote2, vote3]
tally = tally_votes(pk=pk, sk=sk, votes=votes)
expected_tally = 2  # Two "Yes" votes
if tally == expected_tally:
    print(f"- Tally computed correctly: {tally} 'Yes' votes out of {len(votes)}\n")
else:
    error(f"Tally incorrect. Expected {expected_tally}, got {tally}")

print("Step 7: Testing larger election")
large_votes: list[EncryptedVote] = []
yes_count = 7
no_count = 3
for i in range(yes_count):
    large_votes.append(submit_vote(pk=pk, vote=1))
for i in range(no_count):
    large_votes.append(submit_vote(pk=pk, vote=0))
print(f"- {len(large_votes)} votes submitted ({yes_count} Yes, {no_count} No)")

large_tally = tally_votes(pk=pk, sk=sk, votes=large_votes)
if large_tally == yes_count:
    print(f"- Large election tallied correctly: {large_tally} 'Yes' votes\n")
else:
    error(f"Large tally incorrect. Expected {yes_count}, got {large_tally}")

print("Step 8: Testing empty vote list")
empty_tally = tally_votes(pk=pk, sk=sk, votes=[])
if empty_tally == 0:
    print("- Empty vote list handled correctly\n")
else:
    error(f"Empty tally should be 0, got {empty_tally}")

print("Step 9: Testing single vote")
single_vote = [submit_vote(pk=pk, vote=1)]
single_tally = tally_votes(pk=pk, sk=sk, votes=single_vote)
if single_tally == 1:
    print("- Single vote tallied correctly\n")
else:
    error(f"Single vote tally incorrect. Expected 1, got {single_tally}")

print("Step 10: Testing invalid proof detection")
# Create a vote and then try to verify it with wrong public key
wrong_keypair = keyGen()
wrong_pk = cast(Point, wrong_keypair.public_key)
legitimate_vote = submit_vote(pk=pk, vote=1)
is_valid_wrong_pk = verify_proof(
    pk=wrong_pk, ct=legitimate_vote.ciphertext, proof=legitimate_vote.proof
)
if not is_valid_wrong_pk:
    print("- Invalid proof correctly rejected\n")
else:
    error("Invalid proof was incorrectly accepted")

print("Step 11: Testing tally with invalid proof")
valid_vote1 = submit_vote(pk=pk, vote=1)
valid_vote2 = submit_vote(pk=pk, vote=1)
invalid_vote = submit_vote(pk=wrong_pk, vote=1)  # Vote with wrong key
mixed_votes = [valid_vote1, valid_vote2, invalid_vote]
mixed_tally = tally_votes(pk=pk, sk=sk, votes=mixed_votes)
if mixed_tally is False:
    print("- Tally correctly rejected due to invalid proof\n")
else:
    error(f"Tally should have been rejected, but got {mixed_tally}")

print("Step 12: Testing homomorphic property")
# Verify that Enc(m1) + Enc(m2) = Enc(m1 + m2)
m1, m2 = 2, 3
ct1, r1 = encrypt(pk=pk, m=m1)
ct2, r2 = encrypt(pk=pk, m=m2)
ct_sum = add_two_ciphertexts(c1=ct1, c2=ct2)
decrypted_sum = decrypt(sk=sk, c_sum=ct_sum, num_votes=10)
if decrypted_sum == m1 + m2:
    print(f"- Homomorphic property verified: Enc({m1}) + Enc({m2}) = Enc({m1 + m2})\n")
else:
    error(f"Homomorphic property failed. Expected {m1 + m2}, got {decrypted_sum}")

if len(failed_tests) == 0:
    print("=== All Tests Passed! ===")
    print("\nSummary:")
    print("- Key generation works")
    print("- Encryption/decryption works")
    print("- Zero-knowledge proofs work")
    print("- Vote submission works")
    print("- Vote tallying works")
    print("- Invalid proofs are detected and rejected")
    print("- Homomorphic encryption property verified")
else:
    print(f"=== {len(failed_tests)} Test(s) Failed ===")
    print("\nFailed tests:")
    for i, test in enumerate(failed_tests, 1):
        print(f"  {i}. {test}")
    print("\nPlease review the errors above.")
