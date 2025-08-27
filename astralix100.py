import json
import time
import hashlib
import requests
import ecdsa
import binascii
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import socketserver

class Transaction:
    def __init__(self, sender, receiver, amount, tx_type="normal", data=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.tx_type = tx_type
        self.data = data
        self.timestamp = time.time()
        self.hash = self.calculate_hash()
        self.signature = None

    def calculate_hash(self):
        # Create a hash of the transaction
        tx_string = f"{self.sender}{self.receiver}{self.amount}{self.tx_type}{self.data}{self.timestamp}"
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def sign(self, private_key):
        # Sign transaction using sender's private key
        try:
            sk = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key), curve=ecdsa.SECP256k1)
            tx_hash = self.calculate_hash()
            self.signature = binascii.hexlify(sk.sign(tx_hash.encode())).decode()
            return self.signature
        except Exception as e:
            print(f"Error signing transaction: {e}")
            return None

    def verify_signature(self, public_keys):
        # Verify transaction signature
        if self.sender == "system":
            return True  # System transactions don't need signatures
        if self.sender not in public_keys:
            print(f"Public key for {self.sender} not found")
            return False
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_keys[self.sender]), curve=ecdsa.SECP256k1)
            return vk.verify(binascii.unhexlify(self.signature), self.hash.encode())
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, validator):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.validator = validator
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Calculate block hash
        tx_hashes = "".join(tx.hash for tx in self.transactions)
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{tx_hashes}{self.validator}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.current_supply = 10000000.0  # Initial supply of 10M ALX
        self.chain = []
        self.pending_transactions = []
        self.balances = {}
        self.staked_amounts = {}
        self.public_keys = {}
        self.load_data()
        if not self.chain:
            self.chain.append(self.create_genesis_block())
            self.balances["genesis_miner"] = self.current_supply
            self.save_data()

    def create_genesis_block(self):
        # Create first block with initial supply distribution
        genesis_tx = Transaction("system", "genesis_miner", self.current_supply, tx_type="normal")
        genesis = Block(0, "0", 1756276414.6047966, [genesis_tx], "genesis_miner")  # Fixed timestamp
        genesis.hash = "2ce949be2a9eb8cd69b61823043e49c5bfc4379c9a7613b004198d04aa681c45"  # Fixed hash
        return genesis

    def load_data(self):
        # Load chain and state from file
        try:
            with open("astralix100_data.json", "r") as f:
                data = json.load(f)
                self.chain = [Block(b["index"], b["previous_hash"], b["timestamp"],
                                   [Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                                tx["data"], tx["timestamp"]) for tx in b["transactions"]],
                                   b["validator"]) for b in data["chain"]]
                for block in self.chain:
                    for tx in block.transactions:
                        tx.hash = tx.calculate_hash()
                        tx.signature = tx.signature
                    block.hash = block.calculate_hash()
                self.pending_transactions = [Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                                        tx["data"], tx["timestamp"]) for tx in data.get("pending_transactions", [])]
                self.balances = data.get("balances", {})
                self.staked_amounts = data.get("staked_amounts", {})
                self.public_keys = data.get("public_keys", {})
                self.current_supply = data.get("current_supply", self.current_supply)
        except FileNotFoundError:
            print("No data file found, starting fresh")
        except Exception as e:
            print(f"Error loading data: {e}")
            self.chain = []
            self.pending_transactions = []
            self.balances = {}
            self.staked_amounts = {}
            self.public_keys = {}

    def save_data(self):
        # Save chain and state to file
        try:
            data = {
                "chain": [{"index": b.index, "previous_hash": b.previous_hash, "timestamp": b.timestamp,
                          "transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                          "tx_type": tx.tx_type, "data": tx.data, "timestamp": tx.timestamp,
                                          "hash": tx.hash, "signature": tx.signature} for tx in b.transactions],
                          "validator": b.validator, "hash": b.hash} for b in self.chain],
                "pending_transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                        "tx_type": tx.tx_type, "data": tx.data, "timestamp": tx.timestamp,
                                        "hash": tx.hash, "signature": tx.signature} for tx in self.pending_transactions],
                "balances": self.balances,
                "staked_amounts": self.staked_amounts,
                "public_keys": self.public_keys,
                "current_supply": self.current_supply
            }
            with open("astralix100_data.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Data saved to astralix100_data.json")
        except Exception as e:
            print(f"Error saving data: {e}")

    def validate_chain(self):
        # Validate entire chain
        for i, block in enumerate(self.chain):
            if i == 0:
                continue
            if block.previous_hash != self.chain[i-1].hash:
                print(f"Invalid previous hash at block {i}")
                return False
            calculated_hash = block.calculate_hash()
            if block.hash != calculated_hash:
                print(f"Invalid hash at block {i}: received {block.hash}, calculated {calculated_hash}")
                return False
            for tx in block.transactions:
                if not tx.verify_signature(self.public_keys):
                    print(f"Invalid transaction in block {i}: {tx.hash}")
                    return False
        return True

    def add_block(self, block):
        # Add a block to the chain
        if block.previous_hash != self.chain[-1].hash:
            print(f"Block {block.index} rejected: Previous hash mismatch (received {block.previous_hash}, expected {self.chain[-1].hash})")
            return False
        calculated_hash = block.calculate_hash()
        if block.hash != calculated_hash:
            print(f"Block {block.index} rejected: Invalid hash (received {block.hash}, calculated {calculated_hash})")
            return False
        for tx in block.transactions:
            if not tx.verify_signature(self.public_keys):
                print(f"Block {block.index} rejected: Invalid transaction {tx.hash}")
                return False
            if tx.tx_type == "normal" and tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    print(f"Block {block.index} rejected: Insufficient balance for {tx.sender}")
                    return False
        self.chain.append(block)
        for tx in block.transactions:
            if tx.tx_type == "normal":
                if tx.sender != "system":
                    self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount
                self.balances[tx.receiver] = self.balances.get(tx.receiver, 0) + tx.amount
            elif tx.tx_type == "stake":
                self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount
                self.staked_amounts[tx.sender] = self.staked_amounts.get(tx.sender, 0) + tx.amount
            elif tx.tx_type == "unstake":
                self.balances[tx.sender] = self.balances.get(tx.sender, 0) + tx.amount
                self.staked_amounts[tx.sender] = self.staked_amounts.get(tx.sender, 0) - tx.amount
        self.balances[block.validator] = self.balances.get(block.validator, 0) + 10.0  # Mining reward
        self.current_supply += 10.0
        self.save_data()
        print(f"Block {block.index} added successfully")
        return True

    def mine_block(self):
        # Mine pending transactions into a new block
        if not self.pending_transactions:
            print("No transactions to add to block")
            return None
        for tx in self.pending_transactions:
            print(f"Signature verification for {tx.hash}: {tx.verify_signature(self.public_keys)}")
            if not tx.verify_signature(self.public_keys):
                print(f"Pending transaction failed: Invalid signature for {tx.sender}")
                return None
            if tx.tx_type == "normal" and tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    print(f"Pending transaction failed: {tx.sender} has insufficient balance")
                    return None
        validators = list(self.staked_amounts.keys()) or ["genesis_miner"]
        validator = validators[0]  # Simplified: use first validator
        print(f"Selected validator: {validator}")
        new_block = Block(len(self.chain), self.chain[-1].hash, time.time(), self.pending_transactions, validator)
        print(f"Signature verification for {new_block.transactions[0].hash}: {new_block.transactions[0].verify_signature(self.public_keys)}")
        if self.add_block(new_block):
            self.pending_transactions = []
            print(f"Reward 10.0 ALX issued to validator {validator}")
            self.save_data()
            print(f"Block created: Index {new_block.index}, Hash {new_block.hash}")
            return new_block
        return None

class BlockchainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Handle GET requests
        if self.path == "/get_chain":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            chain_data = [{"index": b.index, "previous_hash": b.previous_hash, "timestamp": b.timestamp,
                          "transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                          "tx_type": tx.tx_type, "data": tx.data, "timestamp": tx.timestamp,
                                          "hash": tx.hash, "signature": tx.signature} for tx in b.transactions],
                          "validator": b.validator, "hash": b.hash} for b in blockchain.chain]
            self.wfile.write(json.dumps({"chain": chain_data, "public_keys": blockchain.public_keys}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # Handle POST requests
        if self.path == "/add_block":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            try:
                block_data = json.loads(post_data.decode())
                transactions = [Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                           tx["data"], tx["timestamp"]) for tx in block_data["transactions"]]
                for tx in transactions:
                    tx.hash = tx.hash
                    tx.signature = tx.signature
                new_block = Block(block_data["index"], block_data["previous_hash"],
                                 block_data["timestamp"], transactions, block_data["validator"])
                new_block.hash = block_data["hash"]
                if blockchain.add_block(new_block):
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"message": "Block added successfully"}).encode())
                else:
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Block validation failed"}).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid block data: {str(e)}"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=5000):
    # Start HTTP server
    try:
        server = HTTPServer(("", port), BlockchainHandler)
        print(f"Listening for blocks on 0.0.0.0:{port}")
        server.serve_forever()
    except Exception as e:
        print(f"Error starting HTTP server: {e}")

def sync_with_seed(seed_url):
    # Sync chain with seed node
    try:
        response = requests.get(f"{seed_url}/get_chain")
        if response.status_code == 200:
            data = response.json()
            new_chain = [Block(b["index"], b["previous_hash"], b["timestamp"],
                              [Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                          tx["data"], tx["timestamp"]) for tx in b["transactions"]],
                              b["validator"]) for b in data["chain"]]
            for block in new_chain:
                for tx in block.transactions:
                    tx.hash = tx.calculate_hash()
                    tx.signature = tx.signature
                block.hash = block.calculate_hash()
                print(f"Block created: Index {block.index}, Hash {block.hash}")
            temp_blockchain = Blockchain()
            temp_blockchain.chain = new_chain
            if temp_blockchain.validate_chain():
                print("Chain validation passed")
                preserved_txs = []
                for tx in blockchain.pending_transactions:
                    if tx.verify_signature(data.get("public_keys", {})):
                        preserved_txs.append(tx)
                    else:
                        print(f"Transaction validation failed: Missing signature or public key for {tx.sender}")
                blockchain.chain = new_chain
                blockchain.public_keys.update(data.get("public_keys", {}))
                blockchain.pending_transactions = preserved_txs
                blockchain.balances = {}
                blockchain.staked_amounts = {}
                for block in blockchain.chain:
                    for tx in block.transactions:
                        if tx.tx_type == "normal":
                            if tx.sender != "system":
                                blockchain.balances[tx.sender] = blockchain.balances.get(tx.sender, 0) - tx.amount
                            blockchain.balances[tx.receiver] = blockchain.balances.get(tx.receiver, 0) + tx.amount
                        elif tx.tx_type == "stake":
                            blockchain.balances[tx.sender] = blockchain.balances.get(tx.sender, 0) - tx.amount
                            blockchain.staked_amounts[tx.sender] = blockchain.staked_amounts.get(tx.sender, 0) + tx.amount
                        elif tx.tx_type == "unstake":
                            blockchain.balances[tx.sender] = blockchain.balances.get(tx.sender, 0) + tx.amount
                            blockchain.staked_amounts[tx.sender] = blockchain.staked_amounts.get(tx.sender, 0) - tx.amount
                    blockchain.balances[block.validator] = blockchain.balances.get(block.validator, 0) + 10.0
                blockchain.save_data()
                print(f"Chain synced from {seed_url}, {len(preserved_txs)} pending transactions preserved")
                return True
            else:
                print("Chain validation failed")
        else:
            print(f"Failed to sync: HTTP {response.status_code}")
    except Exception as e:
        print(f"Sync error: {e}")
    return False

def main():
    global blockchain
    blockchain = Blockchain()
    print("Blockchain initialized. Current supply:", blockchain.current_supply, "ALX")
    threading.Thread(target=run_server, daemon=True).start()

    while True:
        print("\n=== AstraliX Blockchain Interface ===")
        print("1. Generate new key pair and address")
        print("2. Register public key (manual)")
        print("3. Send transaction")
        print("4. Stake ALX")
        print("5. Unstake ALX")
        print("6. Check balance")
        print("7. Check staked amount")
        print("8. View chain")
        print("9. Mine block (process pending transactions)")
        print("10. Deploy smart contract")
        print("11. Sync with seed node")
        print("12. Exit")
        choice = input("Enter your choice (1-12): ")

        if choice == "1":
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            private_key = binascii.hexlify(sk.to_string()).decode()
            public_key = binascii.hexlify(sk.get_verifying_key().to_string()).decode()
            address = f"ALX{hashlib.sha256(public_key.encode()).hexdigest()[:40]}"
            print(f"Generated address: {address}")
            blockchain.public_keys[address] = public_key
            blockchain.save_data()
            print(f"New key pair and address generated:\nAddress: {address}\nPrivate Key: {private_key}\nPublic Key: {public_key}")
            print("Save these securely! The address is your wallet identifier.")
            print(f"Registered public key for {address}")

        elif choice == "2":
            address = input("Enter address: ")
            public_key = input("Enter public key: ")
            blockchain.public_keys[address] = public_key
            blockchain.save_data()
            print(f"Registered public key for {address}")

        elif choice == "3":
            sender = input("Enter sender address: ")
            receiver = input("Enter receiver address: ")
            amount = float(input("Enter amount to send: "))
            private_key = input("Enter sender's private key: ")
            tx = Transaction(sender, receiver, amount)
            signature = tx.sign(private_key)
            if signature:
                print(f"Transaction created: {sender} -> {receiver} ({amount} ALX, type: {tx.tx_type})")
                print(f"Transaction signed: {signature}")
                blockchain.pending_transactions.append(tx)
                blockchain.save_data()
                print(f"Added pending transaction: {sender} -> {receiver} ({amount} ALX, type: {tx.tx_type})")
            else:
                print("Failed to create transaction: Invalid signature")

        elif choice == "4":
            address = input("Enter address to stake: ")
            amount = float(input("Enter amount to stake: "))
            private_key = input("Enter private key: ")
            tx = Transaction(address, address, amount, tx_type="stake")
            signature = tx.sign(private_key)
            if signature:
                blockchain.pending_transactions.append(tx)
                blockchain.save_data()
                print(f"Stake transaction created: {amount} ALX")
            else:
                print("Failed to stake: Invalid signature")

        elif choice == "5":
            address = input("Enter address to unstake: ")
            amount = float(input("Enter amount to unstake: "))
            private_key = input("Enter private key: ")
            tx = Transaction(address, address, amount, tx_type="unstake")
            signature = tx.sign(private_key)
            if signature:
                blockchain.pending_transactions.append(tx)
                blockchain.save_data()
                print(f"Unstake transaction created: {amount} ALX")
            else:
                print("Failed to unstake: Invalid signature")

        elif choice == "6":
            address = input("Enter address to check balance: ")
            balance = blockchain.balances.get(address, 0)
            print(f"Balance for {address}: {balance} ALX")

        elif choice == "7":
            address = input("Enter address to check staked amount: ")
            staked = blockchain.staked_amounts.get(address, 0)
            print(f"Staked amount for {address}: {staked} ALX")

        elif choice == "8":
            for block in blockchain.chain:
                print(f"\nBlock {block.index}:")
                print(f"Hash: {block.hash}")
                print(f"Previous Hash: {block.previous_hash}")
                print("Transactions:", [vars(tx) for tx in block.transactions])
                print(f"Validator: {block.validator}")
                print(f"Timestamp: {block.timestamp}")
                print("---")
            print("Chain validation passed" if blockchain.validate_chain() else "Chain validation failed")
            print(f"Is chain valid? {blockchain.validate_chain()}")

        elif choice == "9":
            block = blockchain.mine_block()
            if block:
                try:
                    response = requests.post("https://astralix-87c3a03ccde8.herokuapp.com/add_block",
                                            json={"index": block.index, "previous_hash": block.previous_hash,
                                                  "timestamp": block.timestamp,
                                                  "transactions": [{"sender": tx.sender, "receiver": tx.receiver,
                                                                  "amount": tx.amount, "tx_type": tx.tx_type,
                                                                  "data": tx.data, "timestamp": tx.timestamp,
                                                                  "hash": tx.hash, "signature": tx.signature}
                                                                 for tx in block.transactions],
                                                  "validator": block.validator, "hash": block.hash})
                    print(f"Sending block {block.index} to https://astralix-87c3a03ccde8.herokuapp.com/add_block")
                    if response.status_code == 200:
                        print(f"Block sent successfully to astralix-87c3a03ccde8.herokuapp.com")
                    else:
                        print(f"Failed to send block to astralix-87c3a03ccde8.herokuapp.com: HTTP {response.status_code}, Response: {response.text}")
                except Exception as e:
                    print(f"Failed to send block to astralix-87c3a03ccde8.herokuapp.com: {e}")
                print(f"Current supply after block {block.index}: {blockchain.current_supply} ALX")

        elif choice == "10":
            print("Smart contract deployment not implemented yet")

        elif choice == "11":
            print("Attempting to sync with https://astralix-87c3a03ccde8.herokuapp.com/get_chain")
            if sync_with_seed("https://astralix-87c3a03ccde8.herokuapp.com"):
                print("Successfully synced with seed node")
            else:
                print("Failed to sync with seed node")

        elif choice == "12":
            print("Exiting...")
            break

if __name__ == "__main__":
    main()
