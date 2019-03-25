import hashlib as hasher
import datetime as date
import os
from block import Block
import json
 
class BlockChain:

    def __init__(self):
        self.num_blocks = 0
        self.content=[]
        self.last_block = None

    def hash_function(self, data):
        sha = hasher.sha256()
        d = str(data)
        sha.update(d.encode('utf-8'))
        return sha.hexdigest()


    # functions for repository
    def get_auction_info(self):
        return self.content[0].data

    def get_auction(self):
        return [self.content[0].data] + [b.data for b in self.content] 

    def get_chain_serialized(self):
        return [b.to_json() for b in self.content]

    def get_chain4client(self):
        return [ [str(b),b.to_json()] for b in self.content]
        
    def generate_new_block(self, data):

        # Check if the chain is empty
        if self.last_block == None:
            parent_hash = "root"
        else:
            parent_hash = self.hash_function(self.last_block)           

        # create new block and insert it on the chain
        new_block = Block(len(self.content), data, parent_hash)
        
        return new_block

    def insert_solved_block(self, new_block):
        # Repository validates the puzzle solution
        if self.validate_block( new_block):
            print("Block " + str(new_block.index) + " valid")
            # Repository inserts block into the chain
            self.content.append(new_block)
            # Update last block
            self.last_block = new_block
            if self.validate_chain():
                print("Chain valid")
                return new_block
            return None
        
        # Client sent a wrong solution
        print("Invalid solution!")
        return None


    def validate_block(self, block):
        expected_puzzle_solution = self.solve(block.puzzle_difficulty , block)
        if expected_puzzle_solution == block.puzzle_solution and (block.index ==1 or block.parent_hash == self.hash_function(self.content[block.index-2])):
            return True
        return False

    def validate_chain(self):
        flag = True
        for b in self.content:
            flag = flag and self.validate_block(b)

        return flag
                
    def get_previous_blocks(self, puzzle_solution):
        self.validate_chain()
        l = [b for b in self.content if b.puzzle_solution == puzzle_solution]
        if l == []:
            print("This block doesnt exist!")
            return None

        i = self.content.index(l[0])
        return self.content[:i]
    
    def get_next_blocks(self, m_hash):
        self.validate_chain()
        l = [b for b in self.content if b.block_hash == m_hash]
        if l == []: 
            print("This block doesnt exist!")
            return None

        i = self.content.index(l[0])
        return self.content[i+1:]

    def solve(self, difficulty, block):
        return self.hash_function(json.dumps(block.to_json()))
