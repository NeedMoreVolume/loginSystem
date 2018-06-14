# loginSystem
C++ login system

A login system built in C++. The system uses a username, a password and a salt. 

The salt is uniquely generated each time a user creates an account.
The password the user specifies is hashed once on the client side, then sent server side to be hashed again with the salt and stored.

You can look at the .dat file to see the output of the hash function for the password storage, and the salt for each user made.

This is a good example of how to build a secure login system wherein the underlying file of login data is safe wether the machine is
compromised or not. The hashing algorythm used in this example is the SHA2 algorythm. It is secure, fairly quick, and at the time of writing had no
known collisions making it a suitable algorythm to utilize for password functions.
