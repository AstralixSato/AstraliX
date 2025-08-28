import json
import time
import hashlib
import requests
import ecdsa
import binascii
from aiohttp import web
import threading
import logging
from tenacity import retry, stop_after_attempt, wait_exponential
from inputimeout import inputimeout, TimeoutOccurred

"""
AstraliX Blockchain and ALX Token (Testnet Ready)
==============================
- Simplified Proof-of-Stake (PoS) blockchain with ALX token.
- Optimized for Termux and Heroku with async server and reduced resource usage.
"""

# Configure logging
logging.basicConfig(filename='astralix_server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

GENESIS_PRIVATE_KEY = "7cae72660c82fcb94b256619cc86e7cd4706713ca37652a76d835e3512511179"
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
            logging.info(f"Transaction signed: {self.signature}")
            return self.signature
        except Exception as e:
            logging.error(f"Error signing transaction: {e}")
            return None

    def verify_signature(self, public_keys):
        if self.sender == "system":
            return True
        if self.sender not in public_keys:
            logging.error(f"Signature verification failed: Public key for {self.sender} not found")
            return False
        if not self.signature:
            logging.error(f"Signature verification failed: No signature provided for {self.sender}")
            return False
        try:
            public_key = public_keys[self.sender]
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key), curve=ecdsa.SECP256k1)
            verified = vk.verify(binascii.unhexlify(self.signature), self.hash.encode())
            logging.info(f"Signature verification for {self.hash}: {'Valid' if verified else 'Invalid'}")
            return verified
        except Exception as e:
            logging.error(f"Signature verification failed for {self.sender}: {e}")
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
            logging.info("Invalid chain or no chain found, creating new genesis block")
            self.chain = [self.create_genesis_block()]
            self.balances = {"genesis_miner": self.current_supply}
            self.save_data()
        logging.info(f"Blockchain initialized. Current supply: {self.current_supply} ALX")

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
                logging.info("Data loaded from astralix513.json")
        except FileNotFoundError:
            logging.info("No data file found, starting fresh")
        except Exception as e:
            logging.error(f"Error loading data: {e}")
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
            logging.info("Data saved to astralix513.json")
        except Exception as e:
            logging.error(f"Error saving data: {e}")

    def validate_chain(self):
        for i, block in enumerate(self.chain[-10:]):  # Validate only last 10 blocks
            real_index = len(self.chain) - 10 + i
            if real_index == 0:
                continue
            if block.previous_hash != self.chain[real_index-1].hash:
                logging.error(f"Invalid previous hash at block {real_index}")
                return False
            calculated_hash = block.calculate_hash()
            if block.hash != calculated_hash:
                logging.error(f"Invalid hash at block {real_index}: received {block.hash}, calculated {calculated_hash}")
                return False
            for tx in block.transactions:
                if not tx.verify_signature(self.public_keys):
                    logging.error(f"Invalid transaction in block {real_index}: {tx.hash}")
                    return False
        logging.info("Chain validation passed")
        return True

    def add_block(self, block):
        if block.previous_hash != self.chain[-1].hash:
            logging.error(f"Block {block.index} rejected: Previous hash mismatch")
            return False
        calculated_hash = block.calculate_hash()
        if block.hash != calculated_hash:
            logging.error(f"Block {block.index} rejected: Invalid hash")
            return False
        for tx in block.transactions:
            if not tx.verify_signature(self.public_keys):
                logging.error(f"Block {block.index} rejected: Invalid transaction {tx.hash}")
                return False
            if tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    logging.error(f"Block {block.index} rejected: Insufficient balance for {tx.sender}")
                    return False
        self.chain.append(block)
        for tx in block.transactions:
            if tx.sender != "system":
                self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount
            self.balances[tx.receiver] = self.balances.get(tx.receiver, 0) + tx.amount
        self.balances[block.validator] = self.balances.get(block.validator, 0) + 10.0
        self.current_supply += 10.0
        self.save_data()
        logging.info(f"Block {block.index} added successfully")
        return True

    def mine_block(self):
        if not self.pending_transactions:
            logging.info("No transactions to add to block")
            return None
        valid_transactions = self.pending_transactions[:10]  # Limit to 10 transactions
        for tx in valid_transactions:
            if not tx.verify_signature(self.public_keys):
                logging.error(f"Pending transaction failed: Invalid signature for {tx.sender} (hash: {tx.hash})")
                continue
            if tx.sender != "system":
                if tx.sender not in self.balances or self.balances[tx.sender] < tx.amount:
                    logging.error(f"Pending transaction failed: {tx.sender} has insufficient balance")
                    continue
        if not valid_transactions:
            logging.info("No valid transactions to mine")
            return None
        validator = "genesis_miner"
        logging.info(f"Selected validator: {validator}")
        new_block = Block(len(self.chain), self.chain[-1].hash, time.time(), valid_transactions, validator)
        if self.add_block(new_block):
            self.pending_transactions = [tx for tx in self.pending_transactions if tx not in valid_transactions]
            logging.info(f"Reward 10.0 ALX issued to validator {validator}")
            self.save_data()
            logging.info(f"Block created: Index {new_block.index}, Hash {new_block.hash}")
            return new_block
        return None

    def generate_address(self, public_key):
        return f"ALX{hashlib.sha256(public_key.encode()).hexdigest()[:40]}"

async def handle_get_chain(request):
    chain_data = [{"index": b.index, "previous_hash": b.previous_hash, "timestamp": b.timestamp,
                   "transactions": [{"sender": tx.sender, "receiver": tx.receiver, "amount": tx.amount,
                                    "timestamp": tx.timestamp, "hash": tx.hash, "signature": tx.signature}
                                   for tx in b.transactions],
                   "validator": b.validator, "hash": b.hash} for b in blockchain.chain]
    response = {
        "chain": chain_data,
        "public_keys": blockchain.public_keys,
        "balances": blockchain.balances,
        "current_supply": blockchain.current_supply
    }
    return web.json_response(response)

async def handle_add_block(request):
    try:
        block_data = await request.json()
        transactions = []
        for tx in block_data["transactions"]:
            transaction = Transaction(tx["sender"], tx["receiver"], tx["amount"], tx["timestamp"])
            transaction.hash = tx["hash"]
            transaction.signature = tx["signature"]
            transactions.append(transaction)
        new_block = Block(block_data["index"], block_data["previous_hash"],
                         block_data["timestamp"], transactions, block_data["validator"])
        new_block.hash = block_data["hash"]
        if blockchain.add_block(new_block):
            return web.json_response({"message": "Block added successfully"})
        else:
            return web.json_response({"error": "Block validation failed"}, status=400)
    except Exception as e:
        logging.error(f"Error processing block: {e}")
        return web.json_response({"error": f"Invalid block data: {str(e)}"}, status=400)

def run_async_server(port=5000):
    app = web.Application()
    app.add_routes([web.get('/get_chain', handle_get_chain),
                    web.post('/add_block', handle_add_block)])
    logging.info(f"Starting async server on port {port}")
    web.run_app(app, port=port)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def sync_with_seed(seed_url):
    logging.info(f"Attempting to sync with {seed_url}/get_chain")
    response = requests.get(f"{seed_url}/get_chain", timeout=5)
    response.raise_for_status()
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
        logging.info(f"Block created: Index {block.index}, Hash {block.hash}")
    temp_blockchain = Blockchain()
    temp_blockchain.chain = new_chain
    if temp_blockchain.validate_chain():
        preserved_txs = []
        for tx in blockchain.pending_transactions:
            if tx.verify_signature(data.get("public_keys", {})):
                preserved_txs.append(tx)
            else:
                logging.error(f"Transaction validation failed: Invalid signature for {tx.sender} (hash: {tx.hash})")
        blockchain.chain = new_chain
        blockchain.public_keys.update(data.get("public_keys", {}))
        blockchain.balances = {k: float(v) for k, v in data.get("balances", {}).items()}
        blockchain.current_supply = float(data.get("current_supply", blockchain.current_supply))
        blockchain.pending_transactions = preserved_txs
        blockchain.save_data()
        logging.info(f"Chain synced from {seed_url}, {len(preserved_txs)} pending transactions preserved")
        return True
    else:
        logging.error("Chain validation failed")
        return False

def get_input(prompt, timeout=30):
    try:
        return inputimeout(prompt=prompt, timeout=timeout)
    except TimeoutOccurred:
        logging.info("Input timeout, returning to menu")
        return None

def main():
    global blockchain
    blockchain = Blockchain()
    if 'DYNO' in os.environ:
        logging.info("Running on Heroku, starting server")
        run_async_server(port=int(os.getenv("PORT", 5000)))
    else:
        logging.info("Starting async server in Termux")
        threading.Thread(target=run_async_server, daemon=True).start()
        while True:
            logging.info("Displaying menu")
            print("\n=== AstraliX Blockchain Interface ===")
            print("1. Generate new key pair and address")
            print("2. Register public key (manual)")
            print("3. Send transaction")
            print("4. Check balance")
            print("5. View chain")
            print("6. Mine block (process pending transactions)")
            print("7. Sync with seed node")
            print("8. Exit")
            choice = get_input("Enter your choice (1-8): ")
            if choice is None:
                continue
            choice = choice.strip()

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
                address = get_input("Enter address: ")
                if address is None:
                    continue
                public_key = get_input("Enter public key: ")
                if public_key is None:
                    continue
                blockchain.public_keys[address] = public_key
                blockchain.save_data()
                print(f"Registered public key for {address}")

            elif choice == "3":
                sender = get_input("Enter sender address: ")
                if sender is None:
                    continue
                if sender != "genesis_miner" and sender not in blockchain.public_keys:
                    print(f"Error: No public key registered for {sender}")
                    continue
                receiver = get_input("Enter receiver address: ")
                if receiver is None:
                    continue
                try:
                    amount = float(get_input("Enter amount to send: "))
                    if amount <= 0:
                        print("Amount must be positive")
                        continue
                    private_key = get_input("Enter sender's private key: ")
                    if private_key is None:
                        continue
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
                address = get_input("Enter address to check balance: ")
                if address is None:
                    continue
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
                                                timeout=5)
                        logging.info(f"Sending block {block.index} to Heroku")
                        if response.status_code == 200:
                            print("Block sent successfully to seed node")
                        else:
                            logging.error(f"Failed to send block: HTTP {response.status_code}")
                    except Exception as e:
                        logging.error(f"Failed to send block: {e}")

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
