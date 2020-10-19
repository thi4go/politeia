# Politeia Verify

`politeiaverify` is a simple tool that allows anyone to independently verify that
Politeia has received your proposal and that it is sound. The input received in
this command is the record bundle downloaded from the GUI.

## Usage

`politeiaverify <path to JSON bundle>`

Example:

```
politeiaverify c093b8a808ef68665709995a5a741bd02502b9c6c48a99a4b179fef742ca6b2a.json
Record successfully verified.
```

If the record fails to verify, it will return an error.
