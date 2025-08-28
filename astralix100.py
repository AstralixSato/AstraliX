import json
import time
import hashlib
import requests
import ecdsa
import binascii
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import socketserver
import os

"""
AstraliX Blockchain and ALX Token (Testnet Ready)
==============================
- Proof-of-Stake (PoS) blockchain with ALX token.
- Features:
  - Initial supply: 10M ALX.
  - Block reward: 10 ALX.
  - ECDSA signatures for secure transactions.
  - Wallet addresses with 'ALX' prefix.
  - Support for smart contracts (basic storage).
  - Persistence in astralix513.json.
  - P2P networking with HTTP endpoint for chain sync to Heroku seed node.
- Run with: python astralix100.py
"""

class Transaction:
    def __init__(self, sender, receiver, amount, tx_type="normal", data=None, timestamp=None):
        # Initialize a transaction with sender, receiver, amount, type, data, and timestamp
        self.sender = sender
        self.receiver = receiver
        self.amount = float(amount)
        self.tx_type = tx_type
        self.data = data
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.hash = self.calculate_hash()
        self.signature = None
        print(f"Transaction created: {self.sender} -> {self.receiver} ({self.amount} ALX, type: {self.tx_type})")

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
            print(f"Transaction signed: {self.signature}")
            return self.signature
        except Exception as e:
            print(f"Error signing transaction: {e}")
            return None

    def verify_signature(self, public_keys):
        # Verify transaction signature
        if self.sender == "system":
            return True  # System transactions don't need signatures
        if self.sender not in public_keys:
            print(f"Signature verification failed: Public key for {self.sender} not found")
            return False
        if not self.signature:
            print(f"Signature verification failed: No signature provided for {self.sender}")
            return False
        try:
            public_key = public_keys[self.sender]
            # Validate public key format
            if not public_key.startswith("04") or len(public_key) != 128:
                print(f"Signature verification failed: Invalid public key format for {self.sender}: {public_key}")
                return False
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key), curve=ecdsa.SECP256k1)
            verified = vk.verify(binascii.unhexlify(self.signature), self.hash.encode())
            print(f"Signature verification for {self.hash}: {'Valid' if verified else 'Invalid'}")
            return verified
        except ecdsa.keys.BadSignatureError:
            print(f"Signature verification failed for {self.sender}: Invalid signature")
            return False
        except ecdsa.keys.MalformedPointError:
            print(f"Signature verification failed for {self.sender}: Malformed public key")
            return False
        except Exception as e:
            print(f"Signature verification failed for {self.sender}: {e}")
            return False

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, validator):
        # Initialize block with transactions and validator address
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.validator = validator
        self.hash = self.calculate_hash()
        print(f"Block created: Index {self.index}, Hash {self.hash}")

    def calculate_hash(self):
        # Calculate block hash
        tx_hashes = "".join(tx.hash for tx in self.transactions)
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{tx_hashes}{self.validator}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        # Initialize AstraliX blockchain with initial supply
        self.current_supply = 10000000.0  # Initial supply of 10M ALX
        self.chain = []
        self.pending_transactions = []
        self.balances = {}
        self.staked_amounts = {}
        self.public_keys = {}
        self.contract_states = {}  # Store contract states
        # Register genesis_miner public key (derived from private key 7cae72660c82fcb94b256619cc86e7cd4706713ca37652a76d835e3512511179)
        self.public_keys["genesis_miner"] = "0488e9c2f5e8c9f9e31e6c4b8a6f7e4e7f4b1c9b3e6d9b1e8c7a2f5e4d6b7c8a9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"
        self.load_data()
        if not self.chain or not self.validate_chain():
            print("Invalid chain or no chain found, creating new genesis block")
            self.chain = [self.create_genesis_block()]
            self.balances = {"genesis_miner": self.current_supply}
            self.staked_amounts = {}
            self.contract_states = {}
            self.save_data()
        print(f"Blockchain initialized. Current supply: {self.current_supply} ALX")

    def create_genesis_block(self):
        # Create first block with initial supply distribution
        genesis_tx = Transaction("system", "genesis_miner", self.current_supply, tx_type="normal")
        genesis = Block(0, "0", 1756276414.6047966, [genesis_tx], "genesis_miner")
        genesis.hash = "2ce949be2a9eb8cd69b61823043e49c5bfc4379c9a7613b004198d04aa681c45"  # Fixed hash
        return genesis

    def load_data(self):
        # Load chain and state from file
        try:
            with open("astralix513.json", "r") as f:
                data = json.load(f)
                self.chain = []
                for b in data["chain"]:
                    transactions = []
                    for tx in b["transactions"]:
                        transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                                tx.get("data"), tx["timestamp"])
                        transaction.hash = tx["hash"]
                        transaction.signature = tx["signature"]
                        transactions.append(transaction)
                    block = Block(b["index"], b["previous_hash"], b["timestamp"], transactions, b["validator"])
                    block.hash = b["hash"]
                    self.chain.append(block)
                self.pending_transactions = []
                for tx in data.get("pending_transactions", []):
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                            tx.get("data"), tx["timestamp"])
                    transaction.hash = tx["hash"]
                    transaction.signature = tx["signature"]
                    self.pending_transactions.append(transaction)
                self.balances = {k: float(v) for k, v in data.get("balances", {}).items()}
                self.staked_amounts = {k: float(v) for k, v in data.get("staked_amounts", {}).items()}
                self.public_keys.update(data.get("public_keys", {}))
                self.contract_states = data.get("contract_states", {})
                self.current_supply = float(data.get("current_supply", self.current_supply))
                print(f"Data loaded from astralix513.json")
        except FileNotFoundError:
            print("No data file found, starting fresh")
        except Exception as e:
            print(f"Error loading data: {e}")
            self.chain = []
            self.pending_transactions = []
            self.balances = {}
            self.staked_amounts = {}
            self.contract_states = {}

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
                "contract_states": self.contract_states,
                "current_supply": self.current_supply
            }
            with open("astralix513.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Data saved to astralix513.json")
        except Exception as e:
            print(f"Error saving data: {e}")

    def validate_chain(self):
        # Validate entire chain
        for i, block in enumerate(self.chain):
            if i == 0:
                continue
            if block.previous_hash != self.chain[i-1].hash:
                print(f"Invalid previous hash at block {i}: received {block.previous_hash}, expected {self.chain[i-1].hash}")
                return False
            calculated_hash = block.calculate_hash()
            if block.hash != calculated_hash:
                print(f"Invalid hash at block {i}: received {block.hash}, calculated {calculated_hash}")
                return False
            for tx in block.transactions:
                if not tx.verify_signature(self.public_keys):
                    print(f"Invalid transaction in block {i}: {tx.hash}")
                    return False
        print("Chain validation passed")
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
            elif tx.tx_type == "contract":
                if tx.sender != "system":
                    self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount
                self.balances[tx.receiver] = self.balances.get(tx.receiver, 0) + tx.amount
                self.contract_states[tx.receiver] = tx.data
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
        valid_transactions = []
        for tx in self.pending_transactions:
            if not tx.verify_signature(self.public_keys):
                print(f"Pending transaction failed: Invalid signature for {tx.sender} (hash: {tx.hash})")
                continue
            if tx.tx_type == "normal" and tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    print(f"Pending transaction failed: {tx.sender} has insufficient balance")
                    continue
            valid_transactions.append(tx)
        if not valid_transactions:
            print("No valid transactions to mine")
            return None
        validators = list(self.staked_amounts.keys()) or ["genesis_miner"]
        validator = validators[0]  # Simplified: use first validator
        print(f"Selected validator: {validator}")
        new_block = Block(len(self.chain), self.chain[-1].hash, time.time(), valid_transactions, validator)
        if self.add_block(new_block):
            self.pending_transactions = [tx for tx in self.pending_transactions if tx not in valid_transactions]
            print(f"Reward 10.0 ALX issued to validator {validator}")
            self.save_data()
            print(f"Block created: Index {new_block.index}, Hash {new_block.hash}")
            return new_block
        return None

    def generate_address(self, public_key):
        # Generate a wallet address from public key
        return f"ALX{hashlib.sha256(public_key.encode()).hexdigest()[:40]}"

    def deploy_contract(self, sender, bytecode, amount):
        # Deploy a contract by creating a transaction
        nonce = len([tx for block in self.chain for tx in block.transactions if tx.sender == sender])
        contract_address = f"ALX{hashlib.sha256(f'{bytecode}{sender}{nonce}'.encode()).hexdigest()[:40]}"
        tx = Transaction(sender, contract_address, amount, tx_type="contract", data=bytecode)
        return tx

class BlockchainHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Initialize handler with reference to blockchain
        self.blockchain = blockchain
        super().__init__(*args, **kwargs)

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
                          "validator": b.validator, "hash": b.hash} for b in self.blockchain.chain]
            response = {
                "chain": chain_data,
                "public_keys": self.blockchain.public_keys,
                "balances": self.blockchain.balances,
                "staked_amounts": self.blockchain.staked_amounts,
                "contract_states": self.blockchain.contract_states,
                "current_supply": self.blockchain.current_supply
            }
            self.wfile.write(json.dumps(response).encode())
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
                transactions = []
                for tx in block_data["transactions"]:
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                            tx.get("data"), tx["timestamp"])
                    transaction.hash = tx["hash"]
                    transaction.signature = tx["signature"]
                    transactions.append(transaction)
                new_block = Block(block_data["index"], block_data["previous_hash"],
                                 block_data["timestamp"], transactions, block_data["validator"])
                new_block.hash = block_data["hash"]
                calculated_hash = new_block.calculate_hash()
                if new_block.hash != calculated_hash:
                    print(f"Block validation failed: Invalid hash (received {new_block.hash}, calculated {calculated_hash})")
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Invalid hash: received {new_block.hash}, calculated {calculated_hash}"}).encode())
                    return
                if new_block.previous_hash != self.blockchain.chain[-1].hash:
                    print(f"Block validation failed: Previous hash mismatch (received {new_block.previous_hash}, expected {self.blockchain.chain[-1].hash})")
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Previous hash mismatch: received {new_block.previous_hash}, expected {self.blockchain.chain[-1].hash}"}).encode())
                    return
                for tx in transactions:
                    if not tx.verify_signature(self.blockchain.public_keys):
                        print(f"Block validation failed: Invalid transaction signature for {tx.sender} in block {new_block.index}")
                        self.send_response(400)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": f"Invalid transaction signature for {tx.sender}"}).encode())
                        return
                    if tx.tx_type == "normal" and tx.sender != "system":
                        if tx.sender not in self.blockchain.balances or self.blockchain.balances[tx.sender] < tx.amount:
                            print(f"Block validation failed: Insufficient balance for {tx.sender} in block {new_block.index}")
                            self.send_response(400)
                            self.send_header("Content-type", "application/json")
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": f"Insufficient balance for {tx.sender}"}).encode())
                            return
                if self.blockchain.add_block(new_block):
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"message": "Block added successfully"}).encode())
                else:
                    print(f"Block validation failed: Unknown error for block {new_block.index}")
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Block validation failed: Unknown error"}).encode())
            except Exception as e:
                print(f"Error processing block: {e}")
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
        raise

def sync_with_seed(seed_url):
    # Sync chain with seed node
    try:
        print(f"Attempting to sync with {seed_url}/get_chain")
        response = requests.get(f"{seed_url}/get_chain", timeout=30)
        if response.status_code == 200:
            data = response.json()
            new_chain = []
            for b in data["chain"]:
                transactions = []
                for tx in b["transactions"]:
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["tx_type"],
                                            tx.get("data"), tx["timestamp"])
                    transaction.hash = tx["hash"]
                    transaction.signature = tx["signature"]
                    transactions.append(transaction)
                block = Block(b["index"], b["previous_hash"], b["timestamp"], transactions, b["validator"])
                block.hash = b["hash"]
                new_chain.append(block)
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
                        print(f"Transaction validation failed: Missing signature or public key for {tx.sender} (hash: {tx.hash})")
                blockchain.chain = new_chain
                blockchain.public_keys.update(data.get("public_keys", {}))
                blockchain.balances = {k: float(v) for k, v in data.get("balances", {}).items()}
                blockchain.staked_amounts = {k: float(v) for k, v in data.get("staked_amounts", {}).items()}
                blockchain.contract_states = data.get("contract_states", {})
                blockchain.current_supply = float(data.get("current_supply", blockchain.current_supply))
                blockchain.pending_transactions = preserved_txs
                blockchain.save_data()
                print(f"Chain synced from {seed_url}, {len(preserved_txs)} pending transactions preserved")
                return True
            else:
                print("Chain validation failed")
        else:
            print(f"Failed to sync: HTTP {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"Sync error: {e}")
    print("Sync failed, keeping local chain")
    return False

def main():
    global blockchain
    blockchain = Blockchain()
    print("Blockchain initialized. Current supply:", blockchain.current_supply, "ALX")
    # Check if running on Heroku (DYNO environment variable is set)
    if 'DYNO' in os.environ:
        # On Heroku, start the HTTP server directly
        try:
            run_server(port=int(os.getenv("PORT", 5000)))
        except Exception as e:
            print(f"Error starting HTTP server on Heroku: {e}")
            raise
    else:
        # Locally (e.g., Termux), start HTTP server in background and run interactive interface
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
            choice = input("Enter your choice (1-12): ").strip()

            if choice == "1":
                sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
                private_key = binascii.hexlify(sk.to_string()).decode()
                public_key = binascii.hexlify(sk.get_verifying_key().to_string()).decode()
                address = blockchain.generate_address(public_key)
                blockchain.public_keys[address] = public_key
                blockchain.save_data()
                print(f"Generated address: {address}")
                print(f"Private Key: {private_key}")
                print(f"Public Key: {public_key}")
                print("Save these securely! The address is your wallet identifier.")
                print(f"Registered public key for {address}")

            elif choice == "2":
                address = input("Enter address: ").strip()
                public_key = input("Enter public key: ").strip()
                blockchain.public_keys[address] = public_key
                blockchain.save_data()
                print(f"Registered public key for {address}")

            elif choice == "3":
                sender = input("Enter sender address: ").strip()
                if sender != "genesis_miner" and sender not in blockchain.public_keys:
                    print(f"Error: No public key registered for {sender}")
                    continue
                receiver = input("Enter receiver address: ").strip()
                try:
                    amount = float(input("Enter amount to send: ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    private_key = input("Enter sender's private key: ").strip()
                    # Check for existing transaction to avoid duplication
                    existing_tx = next((tx for tx in blockchain.pending_transactions
                                       if tx.sender == sender and tx.receiver == receiver
                                       and tx.amount == amount and tx.tx_type == "normal"), None)
                    if existing_tx:
                        print(f"Transaction already exists: {sender} -> {receiver} ({amount} ALX, type: normal)")
                        continue
                    # Create and sign transaction
                    tx = Transaction(sender, receiver, amount)
                    signature = tx.sign(private_key)
                    if signature:
                        blockchain.pending_transactions.append(tx)
                        blockchain.save_data()
                        print(f"Transaction created: {sender} -> {receiver} ({amount} ALX, type: {tx.tx_type})")
                        print(f"Transaction signed: {signature}")
                        print(f"Added pending transaction: {sender} -> {receiver} ({amount} ALX, type: {tx.tx_type})")
                    else:
                        print("Failed to create transaction: Invalid signature")
                except ValueError:
                    print("Invalid amount")

            elif choice == "4":
                address = input("Enter address to stake: ").strip()
                try:
                    amount = float(input("Enter amount to stake: ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    private_key = input("Enter private key: ").strip()
                    tx = Transaction(address, address, amount, tx_type="stake")
                    signature = tx.sign(private_key)
                    if signature:
                        blockchain.pending_transactions.append(tx)
                        blockchain.save_data()
                        print(f"Stake transaction created: {amount} ALX")
                    else:
                        print("Failed to stake: Invalid signature")
                except ValueError:
                    print("Invalid amount")

            elif choice == "5":
                address = input("Enter address to unstake: ").strip()
                try:
                    amount = float(input("Enter amount to unstake: ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    private_key = input("Enter private key: ").strip()
                    tx = Transaction(address, address, amount, tx_type="unstake")
                    signature = tx.sign(private_key)
                    if signature:
                        blockchain.pending_transactions.append(tx)
                        blockchain.save_data()
                        print(f"Unstake transaction created: {amount} ALX")
                    else:
                        print("Failed to unstake: Invalid signature")
                except ValueError:
                    print("Invalid amount")

            elif choice == "6":
                address = input("Enter address to check balance: ").strip()
                balance = blockchain.balances.get(address, 0)
                print(f"Balance for {address}: {balance} ALX")

            elif choice == "7":
                address = input("Enter address to check staked amount: ").strip()
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
                                                      "validator": block.validator, "hash": block.hash},
                                                timeout=30)
                        print(f"Sending block {block.index} to https://astralix-87c3a03ccde8.herokuapp.com/add_block")
                        if response.status_code == 200:
                            print(f"Block sent successfully to astralix-87c3a03ccde8.herokuapp.com")
                        else:
                            print(f"Failed to send block: HTTP {response.status_code}, Response: {response.text}")
                    except Exception as e:
                        print(f"Failed to send block: {e}")
                    print(f"Current supply after block {block.index}: {blockchain.current_supply} ALX")

            elif choice == "10":
                sender = input("Enter sender address: ").strip()
                try:
                    amount = float(input("Enter amount to send with contract (0 for none): ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    bytecode = input("Enter contract bytecode (placeholder for future execution): ").strip()
                    tx = blockchain.deploy_contract(sender, bytecode, amount)
                    private_key = input("Enter sender's private key: ").strip()
                    signature = tx.sign(private_key)
                    if signature:
                        blockchain.pending_transactions.append(tx)
                        blockchain.save_data()
                        print(f"Contract deployment transaction created for address: {tx.receiver}")
                    else:
                        print("Failed to deploy contract: Invalid signature")
                except ValueError:
                    print("Invalid amount")

            elif choice == "11":
                print("Attempting to sync with https://astralix-87c3a03ccde8.herokuapp.com/get_chain")
                if sync_with_seed("https://astralix-87c3a03ccde8.herokuapp.com"):
                    print("Successfully synced with seed node")
                else:
                    print("Failed to sync with seed node")

            elif choice == "12":
                print("Exiting...")
                break
            else:
                print("Invalid choice, please try again")

if __name__ == "__main__":
    main()
