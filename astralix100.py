import hashlib
import time
import socket
import threading
import json
import random
import os
import ecdsa
import binascii
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer

"""
AstraliX Blockchain and ALX Token (Testnet Ready)
==============================
- Proof-of-Stake (PoS) blockchain with ALX token.
- Features:
  - Max supply: 100M ALX, initial supply: 10M ALX.
  - Block reward: 10 ALX, halving every 500,000 blocks.
  - ECDSA signatures for secure transactions.
  - Wallet addresses with 'ALX' prefix.
  - Support for smart contracts (basic storage).
  - Persistence in astralix_data.json.
  - P2P networking with HTTP endpoint for chain sync to Heroku seed node.
- Run with: python astralix100.py
"""

class Transaction:
    def __init__(self, sender, receiver, amount, tx_type="normal", data=None, signature=None):
        # Initialize a transaction with sender, receiver, amount, type, data, and optional signature
        self.sender = sender
        self.receiver = receiver
        self.amount = float(amount)
        self.tx_type = tx_type
        self.data = data
        self.timestamp = time.time()
        self.signature = signature
        self.hash = self.calculate_hash()
        print(f"Transaction created: {self.sender} -> {self.receiver} ({self.amount} ALX, type: {self.tx_type})")

    def calculate_hash(self):
        # Calculate SHA-256 hash of transaction (excluding signature)
        value = f"{self.sender}{self.receiver}{self.amount}{self.tx_type}{self.data or ''}{self.timestamp}"
        return hashlib.sha256(value.encode()).hexdigest()

    def sign_transaction(self, private_key):
        # Sign the transaction with the sender's private key
        try:
            sk = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key), curve=ecdsa.SECP256k1)
            self.signature = binascii.hexlify(sk.sign(self.hash.encode())).decode()
            print(f"Transaction signed: {self.hash}")
            return True
        except Exception as e:
            print(f"Error signing transaction: {e}")
            return False

    def verify_signature(self, public_key):
        # Verify the transaction signature with the sender's public key
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key), curve=ecdsa.SECP256k1)
            verified = vk.verify(binascii.unhexlify(self.signature), self.hash.encode())
            print(f"Signature verification for {self.hash}: {'Valid' if verified else 'Invalid'}")
            return verified
        except Exception as e:
            print(f"Error verifying signature: {e}")
            return False

    def to_dict(self):
        # Convert transaction to dictionary for JSON serialization
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "tx_type": self.tx_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "signature": self.signature
        }

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
        # Calculate SHA-256 hash of block
        tx_hashes = "".join(tx.hash for tx in self.transactions)
        value = f"{self.index}{self.previous_hash}{self.timestamp}{tx_hashes}{self.validator}"
        return hashlib.sha256(value.encode()).hexdigest()

    def to_dict(self):
        # Convert block to dictionary for JSON serialization
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "validator": self.validator,
            "hash": self.hash
        }

class AstraliX:
    def __init__(self, max_supply=100_000_000, initial_supply=10_000_000, initial_block_reward=10, halving_interval=500_000):
        # Initialize AstraliX blockchain with supply, PoS, and contract support
        self.max_supply = float(max_supply)
        self.current_supply = float(initial_supply)
        self.initial_block_reward = float(initial_block_reward)
        self.halving_interval = int(halving_interval)
        self.balances = {}
        self.stakers = {}
        self.public_keys = {}
        self.contract_states = {}
        self.peers = []
        self.chain = []
        self.pending_transactions = []
        self.data_file = "astralix_data.json"
        self.seed_nodes = [("astralix-87c3a03ccde8.herokuapp.com", 443)]  # Heroku seed node with HTTPS port
        self.load_data()
        if not self.chain or not self.is_chain_valid():
            print("Invalid chain or no chain found, creating new genesis block")
            self.chain = [self.create_genesis_block()]
            self.balances = {}
            self.stakers = {}
            self.public_keys = {}
            self.contract_states = {}
            self.current_supply = float(initial_supply)
            self.balances["genesis_miner"] = float(initial_supply)
            self.save_data()
        print(f"Blockchain initialized. Current supply: {self.current_supply} ALX")

    def create_genesis_block(self):
        # Create first block with initial supply distribution
        genesis_tx = Transaction("system", "genesis_miner", self.current_supply, tx_type="normal")
        genesis = Block(0, "0", time.time(), [genesis_tx], "genesis_miner")
        return genesis

    def save_data(self):
        # Save chain, balances, stakers, public keys, and contract states to a JSON file
        try:
            data = {
                "chain": [block.to_dict() for block in self.chain],
                "balances": {k: float(v) for k, v in self.balances.items()},
                "stakers": {k: float(v) for k, v in self.stakers.items()},
                "public_keys": self.public_keys,
                "contract_states": self.contract_states,
                "current_supply": float(self.current_supply)
            }
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=4)
            print(f"Data saved to {self.data_file}")
        except Exception as e:
            print(f"Error saving data: {e}")

    def load_data(self):
        # Load chain, balances, stakers, public keys, and contract states from a JSON file
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                self.balances = {k: float(v) for k, v in data["balances"].items()}
                self.stakers = {k: float(v) for k, v in data.get("stakers", {}).items()}
                self.public_keys = data.get("public_keys", {})
                self.contract_states = data.get("contract_states", {})
                self.current_supply = float(data["current_supply"])
                self.chain = []
                for block_data in data["chain"]:
                    transactions = [Transaction(tx["sender"], tx["receiver"], float(tx["amount"]), 
                                               tx.get("tx_type", "normal"), tx.get("data"), tx.get("signature")) 
                                    for tx in block_data["transactions"]]
                    block = Block(block_data["index"], block_data["previous_hash"], 
                                  block_data["timestamp"], transactions, block_data["validator"])
                    block.hash = block_data["hash"]
                    self.chain.append(block)
                print(f"Data loaded from {self.data_file}")
            except Exception as e:
                print(f"Error loading data: {e}")
                self.chain = []
        else:
            print("No data file found, starting with empty chain")

    def sync_chain(self):
        # Sync chain from the Heroku seed node using HTTPS
        for host, port in self.seed_nodes:
            try:
                # Use HTTPS and ignore port for Heroku
                url = f"https://{host}/get_chain"
                print(f"Attempting to sync with {url}")
                response = requests.get(url, timeout=5)  # Reduced timeout for faster feedback
                if response.status_code == 200:
                    data = response.json()
                    self.chain = []
                    for block_data in data["chain"]:
                        transactions = [Transaction(tx["sender"], tx["receiver"], float(tx["amount"]), 
                                                   tx.get("tx_type", "normal"), tx.get("data"), tx.get("signature")) 
                                        for tx in block_data["transactions"]]
                        block = Block(block_data["index"], block_data["previous_hash"], 
                                      block_data["timestamp"], transactions, block_data["validator"])
                        block.hash = block_data["hash"]
                        self.chain.append(block)
                    self.balances = {k: float(v) for k, v in data["balances"].items()}
                    self.stakers = {k: float(v) for k, v in data.get("stakers", {}).items()}
                    self.public_keys = data.get("public_keys", {})
                    self.contract_states = data.get("contract_states", {})
                    self.current_supply = float(data["current_supply"])
                    if self.is_chain_valid():
                        print(f"Chain synced from {host}")
                        self.save_data()
                        return True
                    else:
                        print(f"Invalid chain from {host}")
                        self.chain = [self.create_genesis_block()]
                else:
                    print(f"Failed to sync from {host}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Failed to sync from {host}: {e}")
        print("Sync failed, keeping local chain")
        return False

    def get_current_block_reward(self):
        # Calculate current block reward with halving
        halvings = len(self.chain) // self.halving_interval
        reward = self.initial_block_reward / (2 ** halvings)
        return max(reward, 0.1)

    def update_balances(self, transactions, validator, reward):
        # Validate and update balances based on transactions and reward validator
        temp_balances = self.balances.copy()
        for tx in transactions:
            sender_clean = tx.sender.lstrip("ALX")
            receiver_clean = tx.receiver.lstrip("ALX")
            if tx.tx_type == "normal" and tx.sender != "system":
                if not tx.signature or not self.public_keys.get(sender_clean):
                    print(f"Transaction failed: Missing signature or public key for {tx.sender}")
                    return False
                if not tx.verify_signature(self.public_keys[sender_clean]):
                    print(f"Transaction failed: Invalid signature for {tx.sender}")
                    return False
                if temp_balances.get(sender_clean, 0) < tx.amount:
                    print(f"Transaction failed: {tx.sender} has insufficient balance")
                    return False
                temp_balances[sender_clean] = temp_balances.get(sender_clean, 0) - tx.amount
            elif tx.tx_type == "contract":
                if tx.amount > 0 and temp_balances.get(sender_clean, 0) < tx.amount:
                    print(f"Contract transaction failed: {tx.sender} has insufficient balance")
                    return False
                if tx.amount > 0:
                    temp_balances[sender_clean] = temp_balances.get(sender_clean, 0) - tx.amount
                if tx.data:
                    self.contract_states[receiver_clean] = tx.data
            temp_balances[receiver_clean] = temp_balances.get(receiver_clean, 0) + tx.amount
        self.balances = temp_balances
        validator_clean = validator.lstrip("ALX")
        if self.current_supply + reward <= self.max_supply:
            self.balances[validator_clean] = self.balances.get(validator_clean, 0) + reward
            self.current_supply += reward
            print(f"Reward {reward} ALX issued to validator {validator}")
        else:
            print("Max supply reached: No reward issued")
            reward = 0
        self.save_data()
        return True

    def stake(self, address, amount):
        # Allow user to stake ALX for validation
        try:
            amount = float(amount)
            if amount <= 0:
                print("Stake amount must be positive")
                return False
            address_clean = address.lstrip("ALX")
            if self.balances.get(address_clean, 0) >= amount:
                self.stakers[address_clean] = self.stakers.get(address_clean, 0) + amount
                self.balances[address_clean] -= amount
                print(f"{address} staked {amount} ALX")
                self.save_data()
                return True
            print(f"Stake failed: {address} has insufficient balance")
            return False
        except ValueError:
            print("Invalid stake amount")
            return False

    def unstake(self, address, amount):
        # Allow user to unstake ALX
        try:
            amount = float(amount)
            if amount <= 0:
                print("Unstake amount must be positive")
                return False
            address_clean = address.lstrip("ALX")
            if self.stakers.get(address_clean, 0) >= amount:
                self.stakers[address_clean] -= amount
                self.balances[address_clean] = self.balances.get(address_clean, 0) + amount
                if self.stakers[address_clean] == 0:
                    del self.stakers[address_clean]
                print(f"{address} unstaked {amount} ALX")
                self.save_data()
                return True
            print(f"Unstake failed: {address} has insufficient stake")
            return False
        except ValueError:
            print("Invalid unstake amount")
            return False

    def select_validator(self):
        # Select validator based on stake (weighted random choice)
        if not self.stakers:
            print("No stakers available, defaulting to genesis_miner")
            return "genesis_miner"
        total_stake = sum(self.stakers.values())
        choice = random.uniform(0, total_stake)
        current = 0
        for address, stake in self.stakers.items():
            current += stake
            if current >= choice:
                print(f"Selected validator: ALX{address} with stake {stake}")
                return f"ALX{address}"
        return f"ALX{list(self.stakers.keys())[-1]}"

    def get_latest_block(self):
        # Return the most recent block
        return self.chain[-1]

    def add_pending_transaction(self, transaction):
        # Add a transaction to the pending list
        self.pending_transactions.append(transaction)
        print(f"Added pending transaction: {transaction.sender} -> {transaction.receiver} ({transaction.amount} ALX, type: {transaction.tx_type})")

    def validate_pending_transactions(self):
        # Validate all pending transactions before adding to a block
        temp_balances = self.balances.copy()
        for tx in self.pending_transactions:
            sender_clean = tx.sender.lstrip("ALX")
            receiver_clean = tx.receiver.lstrip("ALX")
            if tx.tx_type == "normal" and tx.sender != "system":
                if not tx.signature or not self.public_keys.get(sender_clean):
                    print(f"Pending transaction failed: Missing signature or public key for {tx.sender}")
                    return False
                if not tx.verify_signature(self.public_keys[sender_clean]):
                    print(f"Pending transaction failed: Invalid signature for {tx.sender}")
                    return False
                if temp_balances.get(sender_clean, 0) < tx.amount:
                    print(f"Pending transaction failed: {tx.sender} has insufficient balance")
                    return False
                temp_balances[sender_clean] = temp_balances.get(sender_clean, 0) - tx.amount
            elif tx.tx_type == "contract":
                if tx.amount > 0 and temp_balances.get(sender_clean, 0) < tx.amount:
                    print(f"Pending contract transaction failed: {tx.sender} has insufficient balance")
                    return False
                if tx.amount > 0:
                    temp_balances[sender_clean] = temp_balances.get(sender_clean, 0) - tx.amount
            temp_balances[receiver_clean] = temp_balances.get(receiver_clean, 0) + tx.amount
        print("All pending transactions validated successfully")
        return True

    def add_block(self, transactions=None):
        # Add new block with PoS validation, using pending transactions if none provided
        if transactions is None:
            transactions = self.pending_transactions
        if not transactions:
            print("No transactions to add to block")
            return False
        validator = self.select_validator()
        reward = self.get_current_block_reward()
        if not self.update_balances(transactions, validator, reward):
            print("Invalid transactions or max supply exceeded")
            return False
        index = len(self.chain)
        previous_hash = self.get_latest_block().hash
        timestamp = time.time()
        new_block = Block(index, previous_hash, timestamp, transactions, validator)
        self.chain.append(new_block)
        self.broadcast_block(new_block)
        print(f"Current supply after block {index}: {self.current_supply} ALX")
        self.pending_transactions = []
        self.save_data()
        return True

    def is_chain_valid(self):
        # Validate chain by checking hashes and transactions
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            calculated_hash = current.calculate_hash()
            if current.hash != calculated_hash:
                print(f"Chain validation failed at block {i}: Hash mismatch (stored: {current.hash}, calculated: {calculated_hash})")
                return False
            if current.previous_hash != previous.hash:
                print(f"Chain validation failed at block {i}: Previous hash mismatch")
                return False
            for tx in current.transactions:
                sender_clean = tx.sender.lstrip("ALX")
                if tx.tx_type == "normal" and tx.sender != "system":
                    if not tx.signature or not self.public_keys.get(sender_clean):
                        print(f"Chain validation failed at block {i}: Missing signature or public key for {tx.sender}")
                        return False
                    if not tx.verify_signature(self.public_keys[sender_clean]):
                        print(f"Chain validation failed at block {i}: Invalid transaction signature")
                        return False
        print("Chain validation passed")
        return True

    def add_peer(self, host, port):
        # Add a peer to the network
        self.peers.append((host, port))
        print(f"Added peer: {host}:{port}")

    def broadcast_block(self, block):
        # Send block to all peers
        for peer in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(peer)
                s.sendall(json.dumps({
                    "index": block.index,
                    "previous_hash": block.previous_hash,
                    "timestamp": block.timestamp,
                    "transactions": [tx.to_dict() for tx in block.transactions],
                    "validator": block.validator,
                    "hash": block.hash
                }).encode())
                s.close()
                print(f"Block broadcasted to {peer}")
            except Exception as e:
                print(f"Failed to broadcast to {peer}: {e}")

    def listen_for_blocks(self, host='0.0.0.0', port=int(os.getenv("PORT", 5000))):
        # Listen for incoming blocks and chain requests via HTTP
        try:
            server = HTTPServer((host, port), lambda *args, **kwargs: AstraliXRequestHandler(self, *args, **kwargs))
            print(f"Listening for blocks on {host}:{port}")
            server.serve_forever()
        except Exception as e:
            print(f"Error starting listener: {e}")

    def generate_address(self, public_key):
        # Generate a wallet address from the public key using SHA-256, prefixed with 'ALX'
        try:
            public_key_bytes = binascii.unhexlify(public_key)
            sha256_hash = hashlib.sha256(public_key_bytes).hexdigest()
            address = "ALX" + sha256_hash[:40]
            print(f"Generated address: {address}")
            return address
        except Exception as e:
            print(f"Error generating address: {e}")
            return None

    def generate_contract_address(self, bytecode, sender, nonce):
        # Generate a unique address for a contract
        try:
            value = f"{bytecode}{sender}{nonce}"
            sha256_hash = hashlib.sha256(value.encode()).hexdigest()
            address = "ALX" + sha256_hash[:40]
            print(f"Generated contract address: {address}")
            return address
        except Exception as e:
            print(f"Error generating contract address: {e}")
            return None

    def generate_key_pair(self):
        # Generate a new ECDSA key pair and derive wallet address
        try:
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            private_key = binascii.hexlify(sk.to_string()).decode()
            public_key = binascii.hexlify(sk.get_verifying_key().to_string()).decode()
            address = self.generate_address(public_key)
            if address is None:
                print("Failed to generate address")
                return None, None, None
            print(f"Key pair generated - Private: {private_key[:10]}..., Public: {public_key[:10]}..., Address: {address}")
            return private_key, public_key, address
        except Exception as e:
            print(f"Error generating key pair: {e}")
            return None, None, None

    def register_user(self, address, public_key):
        # Register a user's public key for signature verification
        address_clean = address.lstrip("ALX")
        if address_clean and public_key:
            self.public_keys[address_clean] = public_key
            print(f"Registered public key for {address}")
            self.save_data()
        else:
            print("Cannot register user: Invalid address or public key")

    def deploy_contract(self, sender, bytecode, amount=0):
        # Deploy a contract by creating a transaction with type "contract"
        sender_clean = sender.lstrip("ALX")
        if sender_clean not in self.public_keys:
            print(f"Error: No public key registered for {sender}")
            return False
        nonce = len([tx for block in self.chain for tx in block.transactions if tx.sender == sender])
        contract_address = self.generate_contract_address(bytecode, sender, nonce)
        if not contract_address:
            print("Failed to generate contract address")
            return False
        tx = Transaction(sender, contract_address, float(amount), tx_type="contract", data=bytecode)
        private_key = input(f"Enter private key for {sender}: ").strip()
        if not tx.sign_transaction(private_key):
            print("Failed to sign contract transaction")
            return False
        self.add_pending_transaction(tx)
        print(f"Contract deployment transaction created for address: {contract_address}")
        return True

    def run_interface(self):
        # Enhanced text-based interface for interacting with the blockchain
        print("\nWelcome to AstraliX Blockchain!")
        print("Use this interface to manage ALX tokens and interact with the blockchain.")
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
                private_key, public_key, address = self.generate_key_pair()
                if private_key and public_key and address:
                    print(f"New key pair and address generated:")
                    print(f"Address: {address}")
                    print(f"Private Key: {private_key}")
                    print(f"Public Key: {public_key}")
                    print("Save these securely! The address is your wallet identifier.")
                    self.register_user(address, public_key)
                else:
                    print("Failed to generate key pair and address")

            elif choice == "2":
                address = input("Enter address: ").strip()
                public_key = input("Enter public key: ").strip()
                if len(public_key) == 128:
                    self.register_user(address, public_key)
                else:
                    print("Invalid public key format")

            elif choice == "3":
                sender = input("Enter sender address: ").strip()
                sender_clean = sender.lstrip("ALX")
                if sender_clean not in self.public_keys:
                    print(f"Error: No public key registered for {sender}")
                    continue
                receiver = input("Enter receiver address: ").strip()
                try:
                    amount = float(input("Enter amount to send: ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    private_key = input("Enter sender's private key: ").strip()
                    tx = Transaction(sender, receiver, amount, tx_type="normal")
                    if tx.sign_transaction(private_key):
                        self.add_pending_transaction(tx)
                    else:
                        print("Failed to sign transaction")
                except ValueError:
                    print("Invalid amount")

            elif choice == "4":
                address = input("Enter address to stake: ").strip()
                try:
                    amount = float(input("Enter amount to stake: ").strip())
                    self.stake(address, amount)
                except ValueError:
                    print("Invalid amount")

            elif choice == "5":
                address = input("Enter address to unstake: ").strip()
                try:
                    amount = float(input("Enter amount to unstake: ").strip())
                    self.unstake(address, amount)
                except ValueError:
                    print("Invalid unstake amount")

            elif choice == "6":
                address = input("Enter address to check balance: ").strip()
                balance = self.balances.get(address.lstrip("ALX"), 0)
                print(f"Balance for {address}: {balance} ALX")

            elif choice == "7":
                address = input("Enter address to check staked amount: ").strip()
                staked = self.stakers.get(address.lstrip("ALX"), 0)
                print(f"Staked amount for {address}: {staked} ALX")

            elif choice == "8":
                for block in self.chain:
                    print(f"\nBlock {block.index}:")
                    print(f"Hash: {block.hash}")
                    print(f"Previous Hash: {block.previous_hash}")
                    print(f"Transactions: {[tx.to_dict() for tx in block.transactions]}")
                    print(f"Validator: {block.validator}")
                    print(f"Timestamp: {block.timestamp}")
                    print("---")
                print(f"Is chain valid? {self.is_chain_valid()}")

            elif choice == "9":
                if self.validate_pending_transactions():
                    self.add_block()
                else:
                    print("Cannot mine block: Invalid pending transactions")

            elif choice == "10":
                sender = input("Enter sender address: ").strip()
                bytecode = input("Enter contract bytecode (placeholder for future execution): ").strip()
                try:
                    amount = float(input("Enter amount to send with contract (0 for none): ").strip())
                    if amount < 0:
                        print("Amount must be non-negative")
                        continue
                    self.deploy_contract(sender, bytecode, amount)
                except ValueError:
                    print("Invalid amount")

            elif choice == "11":
                if self.sync_chain():
                    print("Successfully synced with seed node")
                else:
                    print("Failed to sync with any seed node")

            elif choice == "12":
                print("Exiting interface")
                break

            else:
                print("Invalid choice, please try again")

class AstraliXRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, astralix, *args, **kwargs):
        # Initialize HTTP handler with reference to AstraliX instance
        self.astralix = astralix
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Handle GET requests for chain data
        if self.path == "/get_chain":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            data = {
                "chain": [block.to_dict() for block in self.astralix.chain],
                "balances": self.astralix.balances,
                "stakers": self.astralix.stakers,
                "public_keys": self.astralix.public_keys,
                "contract_states": self.astralix.contract_states,
                "current_supply": self.astralix.current_supply
            }
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_response(404)
            self.end_headers()

# Create AstraliX blockchain
astralix = AstraliX(max_supply=100_000_000, initial_supply=10_000_000, initial_block_reward=10, halving_interval=500_000)

# Run the text-based interface first
astralix.run_interface()

# Start listener in background after interface exits
threading.Thread(target=astralix.listen_for_blocks, args=('0.0.0.0', int(os.getenv("PORT", 5000)))).start()
