from multisig import ECDSAMultiSig

def main():
    # Create a 2-of-3 multisig system
    multisig = ECDSAMultiSig(required_signatures=2, total_participants=3)
    
    # Generate keypairs for three participants
    print("Generating keypairs for participants...")
    participants = [multisig.generate_keypair() for _ in range(3)]
    
    # Add participants to the multisig system
    print("\nAdding participants...")
    for participant in participants:
        multisig.add_participant(participant['public_key'])
    
    # Create a message and its hash
    message = "This is a test message"
    print(f"\nMessage to sign: {message}")
    message_hash = multisig.create_message_hash(message)
    
    # Collect signatures from participants
    print("\nCollecting signatures...")
    signatures = []
    
    # First two participants sign the message
    for i in range(2):
        signature = multisig.sign_message(
            message_hash,
            participants[i]['private_key']
        )
        signatures.append((signature, participants[i]['public_key']))
        print(f"Participant {i} signed the message")
    
    # Verify with two signatures (should succeed)
    print("\nVerifying message with 2 signatures...")
    is_valid = multisig.verify_message(message_hash, signatures)
    print(f"Message verification with 2 signatures: {'Success' if is_valid else 'Failed'}")
    
    # Try with only one signature (should fail)
    print("\nVerifying message with 1 signature...")
    is_valid = multisig.verify_message(message_hash, signatures[:1])
    print(f"Message verification with 1 signature: {'Success' if is_valid else 'Failed'}")
    
    # Try adding the third signature
    print("\nAdding third signature...")
    signature = multisig.sign_message(
        message_hash,
        participants[2]['private_key']
    )
    signatures.append((signature, participants[2]['public_key']))
    is_valid = multisig.verify_message(message_hash, signatures)
    print(f"Message verification with 3 signatures: {'Success' if is_valid else 'Failed'}")

if __name__ == "__main__":
    main()