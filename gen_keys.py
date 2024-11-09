from web3 import Web3
import eth_account
import os

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics

    Each mnemonic is stored on a separate line
    If fewer than (keyId+1) mnemonics have been generated, generate a new one and return that
    """

    w3 = Web3()
    default_private_key = "69593227abfe0f42dea95240ad20f1173618585b38a326352e1076cd0642f157"

    if len(default_private_key) != 64:
        raise ValueError("Provided private key is not 32 bytes (64 hex characters).")

    if os.path.exists(filename):
        with open(filename, 'r') as file:
            lines = file.readlines()
        if keyId < len(lines) and len(lines[keyId].strip()) == 64:
            private_key_hex = lines[keyId].strip()
            private_key = bytes.fromhex(private_key_hex)
        else:
            private_key = bytes.fromhex(default_private_key)
            with open(filename, 'w') as file:
                file.write(default_private_key + '\n')
    else:
        private_key = bytes.fromhex(default_private_key)
        with open(filename, 'w') as file:
            file.write(default_private_key + '\n')

    acct = eth_account.Account.from_key(private_key)
    eth_addr = acct.address

    msg = eth_account.messages.encode_defunct(challenge)
    sig = acct.sign_message(msg)

    assert eth_account.Account.recover_message(msg, signature=sig.signature) == eth_addr, \
        "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
