import hashlib as hasher
import datetime as date
import os
import json

class Block:
    def __init__(self, prev_index, data, parent_hash):
        self.index = prev_index + 1 
        # contains the key pair user-bid
        self.data = data
        self.puzzle_solution = None
        self.puzzle_difficulty = 1
        self.parent_hash = parent_hash
        self.nonce = int.from_bytes(os.urandom(8),  byteorder="big")
        self.timestamp = date.datetime.now()
        
    def __setattr__(self, name, value):
        # records every time an element has been touched
        if name != "timestamp":
            self.timestamp = date.datetime.now()
        self.__dict__[name] = value

    '''
    def __getattr__(self, attr):
        return self.attr
    '''
    def __repr__(self):
        dic = self.to_json()
        dic["Puzzle Solution"] = self.puzzle_solution
        dic["Puzzle Difficulty"] = self.puzzle_difficulty
        return json.dumps(dic)
        
    def to_json(self):
        return {"Data": self.data , "Index":self.index, "Parent Hash": self.parent_hash , "Timestamp":str(self.timestamp), "Nonce":self.nonce}  
