# Motivation for Key Delegation

Following our [first principles](./first-principles.md), delegation lets another
key act within granted permissions without sharing the main private key or
giving up ownership.

## Why a user may want delegation

- **Keep the main key cold.** Use an operational key for everyday tasks while
  the identity key stays offline.
- **Delegate file hosting.** Authorize a homeserver (HS) to host and serve the
  user's files without giving it the user's private key.

## Why a homeserver operator may want delegation

- **Keep the main service key cold.** Delegate online operations to replaceable
  keys while preserving the HS identity.
- **Manage hosting independently.** Rotate keys or change infrastructure within
  granted authority without requiring every user to approve each operational
  change.

## Obvious requirements

- Delegates use their own keys; main private keys remain with their owners.
- Authority is verified through public keys and signatures, independently of
  domain registrars. Invalid authorization must not be accepted.
- Permissions have explicit limits. Hosting files does not grant ownership of
  the identity or prove that the user approved individual responses.
- Owners can replace or revoke delegates without their cooperation, with changes
  taking effect within a defined, bounded period.
- Users retain their identity and content ownership, with a practical way to
  move available files to another HS.

The delegation mechanism remains open.
