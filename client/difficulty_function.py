block = None
blockchain = None

def change():
	l = len(blockchain.content)
	difficulty = (1/(-(l+ ((4 * blockchain.content[0].puzzle_difficulty) + 1)))*5) + 4
	difficulty = round(difficulty)
	block.data["puzzle_difficulty"] = difficulty
	return block, difficulty

block, difficulty = change()
