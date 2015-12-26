# Private-Set-Intersection

Implementing a private set intersection protocol in Java.

The scheme consists of two parties, i.e., a client and a server. Both the client and the server have a set of entries, while the server has also some associated data for each entry.

The client wants to learn the intersection of the two sets without revealing any entries outside the intersection to the server. The server wants to inform the client about common entries without revealing to the client the rest of his entries.

In our implementation both the client and the server have a list of names (client.txt, server.txt), while the server has also some associated data for each name.

**The protocol works as follows:**

The server computes the MD5 and SHA-1 hash functions over each name of his entries. Next, he encrypts the associated data of each entry using AES-128 in CBC mode and an HMAC over the encrypted data using the output of the MD5 hash function as the key. He then sends to the client the output of the SHA-1 function along with their encrypted data and their HMACs.

The client computes the SHA-1 hash function over his entries and compares the output with the hashed entries he received from the server. If he detects a match, he computes the MD5 over the corresponding name and uses it as a key to verify the HMAC. If the HMAC is successfully verified he then proceeds with decrypting the associated data using the MD5 output as a key.

**Important:** The program requires the Java Cryptography Extension (JCE) as well as the apache.commons.codec jar.
