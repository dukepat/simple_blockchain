import time
import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from Block import Block


class Blockchain:
    # Basic blockchain init
    # Includes the chain as a list of blocks in order, pending transactions, and known accounts
    # Includes the current value of the hash target. It can be changed at any point to vary the difficulty
    # Also initiates a genesis block
    def __init__(self, hash_target):
        self._chain = []
        self._pending_transactions = []
        self._chain.append(self.__create_genesis_block())
        self._hash_target = hash_target
        self._accounts = {}

    def __str__(self):
        return f"Chain:\n{self._chain}\n\nPending Transactions: {self._pending_transactions}\n"


    @property
    def hash_target(self):
        return self._hash_target

    @hash_target.setter
    def hash_target(self, hash_target):
        self._hash_target = hash_target

    # Creating the genesis block, taking arbitrary previous block hash since there is no previous block
    # Using the famous bitcoin genesis block string here :)  
    def __create_genesis_block(self):
        genesis_block = Block(0, [], 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks', 
            None, 'Genesis block using same string as bitcoin!')
        return genesis_block

    def __validate_transaction(self, transaction):
        # Digitally verify the signature against hash of the message to validate authenticity
        sender_account = self.get_sender_account(transaction)
        public_pem = sender_account.public_key
        public_key = serialization.load_pem_public_key(public_pem)  # Generating a public key object
        # public_key = sender_account.public_key2
        if self.__verify(public_key, transaction):
            return True
        else:
            return False

    # The verify method to verify the signature using the public key
    def __verify(self, public_key, transaction):
        signature = transaction['signature']
        signature = base64.decodebytes(transaction['signature'])
        hash_message = bytes(hashlib.sha256(json.dumps(transaction['message']).encode('utf-8')).hexdigest(), 'utf-8')
        public_key.verify(
            signature,
            hash_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    def get_sender_account(self, transaction):
        # print(type(transaction), transaction)
        # value = dict(transaction).values()
        # values = list(value)

        for account in self._accounts.values():
            if account.id == transaction["message"]["sender"]:
                sender_account = account
        return sender_account

    def get_receiver_account(self, transaction):
        # value = transaction.values()
        # values = list(value)
        for account in self._accounts.values():
            if account.id == transaction["message"]["receiver"]:
                receiver_account = account
        return receiver_account

    def __process_transactions(self, transactions):
        valid_transactions = []
        invalid_transactions = []
        for transaction in transactions:
            sender_account = self.get_sender_account(transaction)
            receiver_account = self.get_receiver_account(transaction)
            # Appropriately transfer value from the sender to the receiver
            # For all transactions, first check that the sender has enough balance.
            if sender_account.balance >= transaction['message']['value']:
                sender_account.decrease_balance(transaction['message']['value'])
                receiver_account.increase_balance(transaction['message']['value'])
                valid_transactions.append(transaction)
            else:
                invalid_transactions.append(transaction)

        all_transactions = [valid_transactions, invalid_transactions]
        return all_transactions

    # Creates a new block and appends to the chain
    # Also clears the pending transactions as they are part of the new block now
    def create_new_block(self):
        # new_block = Block(len(self._chain), self._pending_transactions, self._chain[-1].block_hash, self._hash_target)
        valid_transactions = self.__process_transactions(self._pending_transactions)[0]
        invalid_transactions = self.__process_transactions(self._pending_transactions)[1]

        new_block = Block(len(self._chain), valid_transactions, self._chain[-1].block_hash, self._hash_target)
        self._chain.append(new_block)
        # Returning invalid transactions to the pending transactions pool
        self._pending_transactions = invalid_transactions
        for transaction in self._pending_transactions:
            sender_account = self.get_sender_account(transaction)
            print(f"\nInvalid transaction traced!\n\n Details:\n [Sender:{transaction['message']['sender']},\n "
                  f"Receiver:{transaction['message']['receiver']}\n"
                  f"Transaction amount: {transaction['message']['value']}\n"
                  f"Sender's balance:{sender_account.balance}.]\n"
                  f"Action: Transaction has been returned to the memepool. It may be processed in another block if sender's "
                  f"balance is greater than amount being sent")
        return new_block

    # Simple transaction with just one sender, one receiver, and one value
    # Created by the account and sent to the blockchain instance
    def add_transaction(self, transaction):
        if self.__validate_transaction(transaction):
            self._pending_transactions.append(transaction)
            return True
        else:
            print(f'ERROR: Transaction: {transaction} failed signature validation')
            return False

    def __validate_chain_hash_integrity(self):
        # Running through the whole blockchain to ensure that previous hash is actually the hash of the previous block
        for index in range(1, len(self._chain)):
            if self._chain[index].previous_block_hash != self._chain[index - 1].hash_block():
                print(f'Previous block hash mismatch in block index: {index}')
                return False
            else:
                return True

    def __validate_block_hash_target(self):
        # Run through the whole blockchain and ensure that block hash meets hash target criteria,
        # and is the actual hash of the block
        # Return False otherwise

        for index in range(1, len(self._chain)):
            if int(self._chain[index].hash_block(), 16) >= int(self._chain[index].hash_target, 16):
                print(f'Hash target not achieved in block index: {index}')
                return False
            else:
                return True

    def __validate_complete_account_balances(self):
        # Running through the whole blockchain to ensure that balances never become negative from any transaction
        # Return False otherwise
        for account in self._accounts.values():
            if account.balance < 0:
                print(f"Error: Account balance validation failed. Account owner (id= {account.id}) "
                      f"has a negative balance ({account.balance})")
                return False
            else:
                return True

    # Blockchain validation method
    # Runs through the whole blockchain and applies appropriate validations
    def validate_blockchain(self):
        # Call __validate_chain_hash_integrity and implement that method. Return False if check fails
        # Call __validate_block_hash_target and implement that method. Return False if check fails
        # Call __validate_complete_account_balances and implement that method. Return False if check fails
        if self.__validate_chain_hash_integrity() and self.__validate_block_hash_target() \
                and self.__validate_complete_account_balances():
            return True
        else:
            return False

    def add_account(self, account):
        self._accounts[account.id] = account

    def get_account_balances(self):
        return [{'id': account.id, 'balance': account.balance} for account in self._accounts.values()]





