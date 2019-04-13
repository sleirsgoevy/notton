## NotTON

This is a (prototype of) a fully decentralized P2P messenger.
Currently, it only operates on UDP sockets.

# How to launch

First, generate a config. file:
python3 genconfig.py > c.json

Then you can run NotTON:
python3 notton.py c.json <bind_addr>-<remote_addr>

Note that address pairs must match exactly for that to work.

# Features

* E2E encryption (see down on how to enable)
* trusted relays
* full mesh routing (currently via total broadcast)
* BitMessage-like anonymous messages (not fully anonymous yet)

# CLI

To send a message to a peer, type:
<peer_id>|<text>

Special commands:

!sendkey <where>
Send own private key to <where>. He will send his messages E2E-encrypted.

!reqkey <where>
Request a private key from <where>. After receiving the key, messages to <where> will be E2E-encrypted.
Issuing !sendkey and !reqkey is enough for full E2E encryption.

!trust <who>
Trust <who>. RELAY requests are only accepted from trusted peers.

!untrust <who>
Untrust <who>.

!relay <who>|<over_who>
Messages to <who> will be RELAYed through <over_who>.

!norelay <who>
Messages to <who> will be sent directly.
