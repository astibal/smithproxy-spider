"""Reference-only addon for the live SOCKS5 authentication probe."""

import json


def socks5_auth(data):
    before = data.valid
    data.valid = data.username == "override" and data.password == "allow"
    peername = data.client_conn.peername
    print("PROBE " + json.dumps({
        "client_host": None if peername is None else peername[0],
        "client_port_present": (
            peername is not None
            and isinstance(peername[1], int)
            and peername[1] > 0
        ),
        "username": data.username,
        "password": data.password,
        "valid_before": before,
        "valid_after": data.valid,
    }), flush=True)
