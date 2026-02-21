# Protocol enum — stored as INTEGER in knocks/proto intel tables
PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3}
PROTO_NAME = {v: k for k, v in PROTO.items()}  # reverse lookup: 0->'SSH' etc.
