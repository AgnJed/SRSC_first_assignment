# Notes from the PA.pdf

## 1. Introduction
Goal is to create an api that can be used to "implement datagram secure transport channels for applications developed in Java" meaning: make an app that can be put in front of other to allow secure communication between them.

Needs to be able to:
- Generic enough to be used by any application based on DSTP Java Sockets
- Must be leveraged by DSTP and UDP anabled Datagram Sockets.

### 1.1 Adversary Model condicions and DSTP security properties

DSTP and DSTP sockets will provide security guarantees for the following properties:
- Message connectionless integrity without recovery to protect message tampering in UDP exchanged payloads and integrity of UDP packets
- Message authenticity preserving the authenticity of send/received messages 
- Message connectionless confidentiality

The included integrity guarantees must provide traffic ordering integrity, allowing receivers to discard out-of-order packets (**not recoverable packet losses and discarding of out order packets**), only processing packets with right sequence order.