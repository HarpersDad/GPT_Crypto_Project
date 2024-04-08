import hashlib
import json
from time import time
import rsa
import socket
import threading
import requests
from urllib.parse import urlparse


class CryptoWallet:
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)

    def generate_address(self):
        if not self.public_key:
            raise ValueError("Public key not generated")
        return hashlib.sha256(self.public_key.save_pkcs1()).hexdigest()

    def sign_transaction(self, transaction):
        if not self.private_key:
            raise ValueError("Private key not generated")
        transaction_string = json.dumps(transaction, sort_keys=True)
        return rsa.sign(transaction_string.encode(), self.private_key, 'SHA-256')

    @staticmethod
    def verify_transaction(transaction, public_key, signature):
        if not public_key:
            raise ValueError("Public key not provided")
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            rsa.verify(transaction_string.encode(), signature, rsa.PublicKey.load_pkcs1(public_key))
            return True
        except rsa.VerificationError:
            return False


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.max_supply = 21_000_000
        self.new_block(previous_hash='1', proof=100, initial_supply=0)

    def new_block(self, proof, previous_hash=None, initial_supply=0):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'initial_supply': initial_supply
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        total_supply = sum(block['initial_supply'] for block in self.chain) + amount
        if total_supply > self.max_supply:
            raise ValueError("Maximum supply cap reached. No more coins can be created.")
        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount, 'signature': signature}
        self.current_transactions.append(transaction)
        return self.last_block['index'] + 1

    def register_node(self, node_address):
        parsed_url = urlparse(node_address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        last_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != self.hash(last_block) or not self.valid_proof(last_block['proof'],
                                                                                       block['proof']):
                return False
            last_block = block
        return True

    def resolve_conflicts(self):
        max_length = len(self.chain)
        new_chain = None
        for node in self.nodes:
            try:
                response = requests.get(f'https://{node}/chain')
                if response.status_code == 200:
                    length, chain = response.json()['length'], response.json()['chain']
                    if length > max_length and self.valid_chain(chain):
                        max_length, new_chain = length, chain
            except requests.exceptions.RequestException as resolve_conflicts_error:
                print(f"Error communicating with node {node}: {resolve_conflicts_error}")
        if new_chain:
            self.chain = new_chain
            return True
        return False

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    @property
    def last_block(self):
        return self.chain[-1]


app = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
app.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
app.bind(('0.0.0.0', 5000))
app.listen(5)

blockchain = Blockchain()
wallet = CryptoWallet()


def handle_client_connection(client_socket):
    try:
        request = client_socket.recv(1024)
        response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
        request.send(json.dumps(response).encode())
        request.close()
    except Exception as client_connection_error:
        print(f"Error handling client connection: {client_connection_error}")
        client_socket.close()


while True:
    try:
        client_sock, address = app.accept()
        print('Accepted connection from {}'.format(address))
        client_handler = threading.Thread(target=handle_client_connection, args=(client_sock,))
        client_handler.start()
    except Exception as e:
        print(f"Error accepting connection: {e}")
