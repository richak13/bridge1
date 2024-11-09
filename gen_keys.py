from web3 import Web3
import eth_account
import os

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics

    Each mnemonic is stored on a separate line.
    If fewer than (keyId+1) mnemonics have been generated, generate a new one and return that.
    """

    w3 = Web3()
    default_private_key = "69593227abfe0f42dea95240ad20f1173618585b38a326352e1076cd0642f157"

    # Ensure the default private key is valid (32 bytes in hex format)
    if len(default_private_key) != 64:
        raise ValueError("Provided private key is not 32 bytes (64 hex characters).")

    # Check if eth_mnemonic.txt exists and has keys; if not, use the default key provide
    if os.path.exists(filename) and os.path.getsize(filename) > 0:
        with open(filename, 'r') as file:
            lines = file.readlines()
        if keyId < len(lines):
            private_key_hex = lines[keyId].strip()
            if len(private_key_hex) != 64:  # Verify correct length
                raise ValueError("Stored private key is not 32 bytes (64 hex characters).")
            private_key = bytes.fromhex(private_key_hex)
        else:
            private_key = bytes.fromhex(default_private_key)
            with open(filename, 'a') as file:
                file.write(default_private_key + '\n')
    else:
        private_key = bytes.fromhex(default_private_key)
        with open(filename, 'w') as file:
            file.write(default_private_key + '\n')

    # Derive Ethereum account from the private key
    acct = eth_account.Account.from_key(private_key)
    eth_addr = acct.address

    # Sign the challenge message
    msg = eth_account.messages.encode_defunct(challenge)
    sig = acct.sign_message(msg)

    # Verification assertion
    assert eth_account.Account.recover_message(msg, signature=sig.signature) == eth_addr, \
        "Failed to sign message properly"

    # Return the signature and address
    return sig.signature.hex(), eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
