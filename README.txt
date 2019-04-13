## NotTON

This is a (prototype of) a fully decentralized P2P messenger.
Currently, it only operates on UDP sockets.

# How to launch

First, generate a config. file:
python3 genconfig.py > c.json

Then you can run NotTON:
python3 notton.py c.json

Note that no sockets are connected by default. Use !socket to create a new one.

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

!forward <who>|<msgid>
Forward message <msgid> to <who>

!sendpeer <to_who>|<who>
Send contact <who> to <to_who>

!sendfile <to_who>|<file>
Send contact from <file> to <to_who>

!import <msgid>
Import contact from message <msgid>

!importfile <file>
Import contact from <file>

!socket <proto>://<params>
Create a new socket.
* For UDP, it is udp://<bind_addr>:<bind_port>-<remote_addr>:<remote_port>.
  Note that UDP socket must be created symmetrically on both sides to work.
* For UDP broadcast, it is udpbroadcast://<bind_addr>:<bind_port>.
  <bind_addr> should be empty. <bind_port> should be the same on both sides to work.

!nickname <who>@<nickname>
Set a nickname <nickname> for <who>.
<who> can be later specified as @<nickname>.
Nickname will be included in a contact, even if specified by ID.
