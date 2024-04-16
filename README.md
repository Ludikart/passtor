# Passtor

This program stores passwords and usernames in a database on a server and the user can then access them connected through the tor-network. The user logs in and can retrieve one password at a time from the server's database.

This is probably not the best way to store and get passwords from a server. It would probably be better to just have a single database file, which you store locally and update to and from the server periodically. This project is mostly for demonstration purposes.

The application users must be added locally using the databasefunctions cli. The user can then log in through the internet.