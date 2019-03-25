bid = None
user = None
bids = None
auction_id = None
def validate():
	v = (bids == None) or (user not in [b[0] for b in bids])
	return v
valid = validate()