# Private-Set-Intersection

*Important*: The program requires the Java Cryptography Extension (JCE) as well as the apache.commons.codec jar.

Implementing a private set intersection protocol in Java.

The scheme consists of two parties, i.e., a client and a server. Both the client and the server have a set of entries while the server also has some associated data for each entry.

The client wants to learn the intersection of the two sets without revealing any entries outside the intersection to the server. The server wants to inform the client about common entries without revealing to the client all of his entries.

In our implementation both the client and the server have a list of unique names (client.txt, server.txt), while the server has also some associated data for each name.
