# Compromised Credential Detection Service (CCDS)

The Compromised Credential Detection Service (CCDS) is a mechanism to quickly check a pair of login credentials (username and password) against a database of publicly known (“compromised”) credentials. At a high level, a participating authentication service one-way encrypts a pair of credentials client-side, sends the hash to CCDS, and receives whether the hash exists in the database. By using this service, authentication gains the ability to warn users when a password becomes a security risk and needs to be changed.

## Relevant References

- https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03
- https://www.cryptolux.org/images/0/0d/Argon2.pdf
