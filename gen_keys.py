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

    # Use the provided private key if the file is empty or doesn't exist
    if not os.path.exists(filename) or os.stat(filename).st_size == 0:
        private_key = bytes.fromhex("380A72Da9b73bf597d7f840D21635CEE26aa3dCf"[2:])  # Strip '0x' prefix
        with open(filename, 'w') as file:
            file.write("380A72Da9b73bf597d7f840D21635CEE26aa3dCf\n")
    else:
        with open(filename, 'r') as file:
            lines = file.readlines()
        if keyId >= len(lines):
            new_account = eth_account.Account.create()
            private_key = new_account.key
            with open(filename, 'a') as file:
                file.write(new_account.key.hex() + '\n')
        else:
            private_key = bytes.fromhex(lines[keyId].strip())

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
