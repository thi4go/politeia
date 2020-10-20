# Politeia Verify

`politeiaverify` is a simple tool that allows anyone to independently verify 
that Politeia has received your proposal/comment and that it is sound. The 
input received in this command is the json bundle downloaded from the GUI.

## Usage

`politeiaverify [flags] <path to JSON bundle>`

Flags:
  `-proposal` - verify proposal bundle
  `-comments` - verify comments bundle

Examples:

```
politeiaverify -proposal c093b8a808ef68665709995a5a741bd02502b9c6c48a99a4b179fef742ca6b2a.json

Proposal  successfully verified.
```

```
politeiaverify -comments c093b8a808ef68665709995a5a741bd02502b9c6c48a99a4b179fef742ca6b2a-comments.json

Comments  successfully verified.
```

If the bundle fails to verify, it will return an error.
