import json
import time
import hashlib
import requests
import ecdsa
import binascii
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import os
from contextlib import redirect_stdout
import logging

"""
AstraliX Blockchain and ALX Token (Testnet Ready)
==============================
- Simplified Proof-of-Stake (PoS) blockchain with ALX token.
- Features:
  - Initial supply: 10M ALX.
  - Block reward: 10 ALX.
  - ECDSA signatures for secure transactions.
  - Wallet addresses with 'ALX' prefix.
  - Persistence in astralix513.json.
  - P2P networking with HTTP endpoint for chain sync to Heroku seed node.
- Run with: python astralix100.py
"""

# Configure logging for server messages
logging.basicConfig(filename='astralix_server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Predefined private key for genesis_miner
GENESIS_PRIVATE_KEY = "7cae72660c82fcb94b256619cc86e7cd4706713ca37652a76d835e3512511179"

# Predefined public key for genesis_miner (derived from the private key)
GENESIS_PUBLIC_KEY = "0488e9c2f5e8c9f9e31e6c4b8a6f7e4e7f4b1c9b3e6d9b1e8c7a2f5e4d6b7c8a9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"

class Transaction:
    def __init__(self, sender, receiver, amount, timestamp=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = float(amount)
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.hash = self.calculate_hash()
        self.signature = None

    def calculate_hash(self):
        tx_string = f"{self.sender}{self.receiver}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def sign(self, private_key):
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
        if self.sender == "system":
            return True
        if self.sender not in public_keys:
            print(f"Signature verification failed: Public key for {self.sender} not found")
            return False
        if not self.signature:
            print(f"Signature verification failed: No signature provided for {self.sender}")
            return False
        try:
            public_key = public_keys[self.sender]
            if not public_key.startswith("04") or len(public_key) != 128:
                print(f"Signature verification failed: Invalid public key format for {self.sender}: {public_key}")
                return False
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key), curve=ecdsa.SECP256k1)
            verified = vk.verify(binascii.unhexlify(self.signature), self.hash.encode())
            print(f"Signature verification for {self.hash}: {'Valid' if verified else 'Invalid'}")
            return verified
        except Exception as e:
            print(f"Signature verification failed for {self.sender}: {e}")
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
        tx_hashes = "".join(tx.hash for tx in self.transactions)
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{tx_hashes}{self.validator}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.current_supply = 10000000.0
        self.chain = []
        self.pending_transactions = []
        self.balances = {}
        self.public_keys = {"genesis_miner": GENESIS_PUBLIC_KEY}
        self.load_data()
        if not self.chain or not self.validate_chain():
            print("Invalid chain or no chain found, creating new genesis block")
            self.chain = [self.create_genesis_block()]
            self.balances = {"genesis_miner": self.current_supply}
            self.save_data()
        print(f"Blockchain initialized. Current supply: {self.current_supply} ALX")

    def create_genesis_block(self):
        genesis_tx = Transaction("system", "genesis_miner", self.current_supply)
        genesis = Block(0, "0", time.time(), [genesis_tx], "genesis_miner")
        return genesis

    def load_data(self):
        try:
            with open("astralix513.json", "r") as f:
                data = json.load(f)
                self.chain = []
                for b in data["chain"]:
                    transactions = []
                    for tx in b["transactions"]:
                        transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["timestamp"])
                        transaction.hash = tx["hash"]
                        transaction.signature = tx["signature"]
                        transactions.append(transaction)
                    block = Block(b["index"], b["previous_hash"], b["timestamp"], transactions, b["validator"])
                    block.hash = b["hash"]
                    self.chain.append(block)
                self.pending_transactions = []
                for tx in data.get("pending_transactions", []):
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["timestamp"])
                    transaction.hash = tx["hash"]
                    transaction.signature = tx["signature"]
                    self.pending_transactions.append(transaction)
                self.balances = {k: float(v) for k, v in data.get("balances", {}).items()}
                self.public_keys.update(data.get("public_keys", {}))
                print(f"Data loaded from astralix513.json")
        except FileNotFoundError:
            print("No data file found, starting fresh")
        except Exception as e:
            print(f"Error loading data: {e}")
            self.chain = []
            self.pending_transactions = []
            self.balances = {}

    def save_data(self):
        try:
            data = {
                "chain": [{"index": b.index, "previous_hash": b.previous_hash, "timestamp": b.timestamp,
                          "transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                           "timestamp": tx.timestamp, "hash": tx.hash, "signature": tx.signature}
                                          for tx in b.transactions],
                          "validator": b.validator, "hash": b.hash} for b in self.chain],
                "pending_transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                        "timestamp": tx.timestamp, "hash": tx.hash, "signature": tx.signature}
                                       for tx in self.pending_transactions],
                "balances": self.balances,
                "public_keys": self.public_keys,
                "current_supply": self.current_supply
            }
            with open("astralix513.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Data saved to astralix513.json")
        except Exception as e:
            print(f"Error saving data: {e}")

    def validate_chain(self):
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
        if block.previous_hash != self.chain[-1].hash:
            print(f"Block {block.index} rejected: Previous hash mismatch")
            return False
        calculated_hash = block.calculate_hash()
        if block.hash != calculated_hash:
            print(f"Block {block.index} rejected: Invalid hash")
            return False
        for tx in block.transactions:
            if not tx.verify_signature(self.public_keys):
                print(f"Block {block.index} rejected: Invalid transaction {tx.hash}")
                return False
            if tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    print(f"Block {block.index} rejected: Insufficient balance for {tx.sender}")
                    return False
        self.chain.append(block)
        for tx in block.transactions:
            if tx.sender != "system":
                self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount
            self.balances[tx.receiver] = self.balances.get(tx.receiver, 0) + tx.amount
        self.balances[block.validator] = self.balances.get(block.validator, 0) + 10.0
        self.current_supply += 10.0
        self.save_data()
        print(f"Block {block.index} added successfully")
        return True

    def mine_block(self):
        if not self.pending_transactions:
            print("No transactions to add to block")
            return None
        valid_transactions = []
        for tx in self.pending_transactions:
            if not tx.verify_signature(self.public_keys):
                print(f"Pending transaction failed: Invalid signature for {tx.sender} (hash: {tx.hash})")
                continue
            if tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    print(f"Pending transaction failed: {tx.sender} has insufficient balance")
                    continue
            valid_transactions.append(tx)
        if not valid_transactions:
            print("No valid transactions to mine")
            return None
        validator = "genesis_miner"
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
        return f"ALX{hashlib.sha256(public_key.encode()).hexdigest()[:40]}"

class BlockchainHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.blockchain = blockchain
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/get_chain":
            try:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                chain_data = [{"index": b.index, "previous_hash": b.previous_hash, "timestamp": b.timestamp,
                              "transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                               "timestamp": tx.timestamp, "hash": tx.hash, "signature": tx.signature}
                                              for tx in b.transactions],
                              "validator": b.validator, "hash": b.hash} for b in self.blockchain.chain]
                response = {
                    "chain": chain_data,
                    "public_keys": self.blockchain.public_keys,
                    "balances": self.blockchain.balances,
                    "current_supply": self.blockchain.current_supply
                }
                self.wfile.write(json.dumps(response).encode())
                logging.info("Successfully sent chain data")
            except Exception as e:
                logging.error(f"Error in do_GET: {e}")
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Server error: {str(e)}"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/add_block":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            try:
                block_data = json.loads(post_data.decode())
                transactions = []
                for tx in block_data["transactions"]:
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["timestamp"])
                    transaction.hash = tx["hash"]
                    transaction.signature = tx["signature"]
                    transactions.append(transaction)
                new_block = Block(block_data["index"], block_data["previous_hash"],
                                 block_data["timestamp"], transactions, block_data["validator"])
                new_block.hash = block_data["hash"]
                if self.blockchain.add_block(new_block):
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"message": "Block added successfully"}).encode())
                else:
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Block validation failed"}).encode())
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
    try:
        if 'DYNO' not in os.environ:
            with open('astralix_server.log', 'a') as f:
                with redirect_stdout(f):
                    server = HTTPServer(("", port), BlockchainHandler)
                    logging.info(f"Listening for blocks on 0.0.0.0:{port}")
                    server.serve_forever()
        else:
            server = HTTPServer(("", port), BlockchainHandler)
            print(f"Listening for blocks on 0.0.0.0:{port}")
            server.serve_forever()
    except Exception as e:
        logging.error(f"Error starting HTTP server: {e}")
        print(f"Error starting HTTP server: {e}")
        raise

def sync_with_seed(seed_url):
    try:
        print(f"Attempting to sync with {seed_url}/get_chain")
        response = requests.get(f"{seed_url}/get_chain", timeout=20)
        print(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            new_chain = []
            for b in data["chain"]:
                transactions = []
                for tx in b["transactions"]:
                    transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["timestamp"])
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
                        print(f"Transaction validation failed: Invalid signature for {tx.sender} (hash: {tx.hash})")
                blockchain.chain = new_chain
                blockchain.public_keys.update(data.get("public_keys", {}))
                blockchain.balances = {k: float(v) for k, v in data.get("balances", {}).items()}
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
    if 'DYNO' in os.environ:
        try:
            run_server(port=int(os.getenv("PORT", 5000)))
        except Exception as e:
            print(f"Error starting HTTP server on Heroku: {e}")
            raise
    else:
        threading.Thread(target=run_server, daemon=True).start()
        while True:
            print("\n=== AstraliX Blockchain Interface ===")
            print("1. Generate new key pair and address")
            print("2. Register public key (manual)")
            print("3. Send transaction")
            print("4. Check balance")
            print("5. View chain")
            print("6. Mine block (process pending transactions)")
            print("7. Sync with seed node")
            print("8. Exit")
            choice = input("Enter your choice (1-8): ").strip()

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
                    if amount <= 0:
                        print("Amount must be positive")
                        continue
                    private_key = input("Enter sender's private key: ").strip()
                    existing_tx = next((tx for tx in blockchain.pending_transactions
                                       if tx.sender == sender and tx.receiver == receiver
                                       and tx.amount == amount), None)
                    if existing_tx:
                        print(f"Transaction already exists: {sender} -> {receiver} ({amount} ALX)")
                        continue
                    tx = Transaction(sender, receiver, amount)
                    signature = tx.sign(private_key)
                    if signature:
                        blockchain.pending_transactions.append(tx)
                        blockchain.save_data()
                        print(f"Transaction created: {sender} -> {receiver} ({amount} ALX)")
                        print(f"Transaction signed: {signature}")
                    else:
                        print("Failed to create transaction: Invalid signature")
                except ValueError:
                    print("Invalid amount")

            elif choice == "4":
                address = input("Enter address to check balance: ").strip()
                balance = blockchain.balances.get(address, 0)
                print(f"Balance for {address}: {balance} ALX")

            elif choice == "5":
                for block in blockchain.chain:
                    print(f"\nBlock {block.index}:")
                    print(f"Hash: {block.hash}")
                    print(f"Previous Hash: {block.previous_hash}")
                    print("Transactions:", [vars(tx) for tx in block.transactions])
                    print(f"Validator: {block.validator}")
                    print(f"Timestamp: {block.timestamp}")
                    print("---")
                print(f"Is chain valid? {blockchain.validate_chain()}")

            elif choice == "6":
                block = blockchain.mine_block()
                if block:
                    try:
                        response = requests.post("https://astralix-87c3a03ccde8.herokuapp.com/add_block",
                                                json={"index": block.index, "previous_hash": block.previous_hash,
                                                      "timestamp": block.timestamp,
                                                      "transactions": [{"sender": tx.sender, "receiver": tx.receiver,
                                                                       "amount": tx.amount, "timestamp": tx.timestamp,
                                                                       "hash": tx.hash, "signature": tx.signature}
                                                                      for tx in block.transactions],
                                                      "validator": block.validator, "hash": block.hash},
                                                timeout=20)
                        print(f"Sending block {block.index} to https://astralix-87c3a03ccde8.herokuapp.com/add_block")
                        if response.status_code == 200:
                            print("Block sent successfully to seed node")
                        else:
                            print(f"Failed to send block: HTTP {response.status_code}, Response: {response.text}")
                    except Exception as e:
                        print(f"Failed to send block: {e}")

            elif choice == "7":
                if sync_with_seed("https://astralix-87c3a03ccde8.herokuapp.com"):
                    print("Successfully synced with seed node")
                else:
                    print("Failed to sync with seed node")

            elif choice == "8":
                print("Exiting...")
                break
            else:
                print("Invalid choice, please try again")

if __name__ == "__main__":
    main()
