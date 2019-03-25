bid = None
user = None
bids = None
auction_id = None
def validate():
	if len(bids) == 0:
		return float(bid) > 0

	max_val = max([ float(b[1]) for b in bids])
	return float(bid) > max_val

valid = validate()