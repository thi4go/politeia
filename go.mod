module github.com/thi4go/politeia

go 1.13

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/dajohi/goemail v1.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/blockchain/stake v1.1.0
	github.com/decred/dcrd/certgen v1.1.0
	github.com/decred/dcrd/chaincfg v1.5.1
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/dcrec/secp256k1 v1.0.2
	github.com/decred/dcrd/dcrutil v1.4.0
	github.com/decred/dcrd/hdkeychain v1.1.1
	github.com/decred/dcrd/wire v1.3.0
	github.com/decred/dcrdata/api/types/v4 v4.0.4
	github.com/decred/dcrdata/explorer/types/v2 v2.1.1
	github.com/decred/dcrdata/pubsub/types/v3 v3.0.5
	github.com/decred/dcrdata/pubsub/v4 v4.0.3-0.20191219212733-19f656d6d679
	github.com/decred/dcrdata/semver v1.0.0
	github.com/decred/dcrtime v0.0.0-20191018193024-8d8b4ef0458e
	github.com/decred/dcrwallet v1.2.3-0.20190128160919-849f7c01c12d
	github.com/decred/dcrwallet/rpc/walletrpc v0.2.0
	github.com/decred/go-socks v1.1.0
	github.com/decred/politeia v0.0.0-00010101000000-000000000000 // indirect
	github.com/decred/slog v1.0.0
	github.com/go-test/deep v1.0.1
	github.com/golang/protobuf v1.3.2
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/trillian v1.2.2-0.20190612132142-05461f4df60a
	github.com/google/uuid v1.1.1
	github.com/gorilla/csrf v1.6.2
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/schema v1.1.0
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.0
	github.com/gorilla/websocket v1.4.1
	github.com/grpc-ecosystem/grpc-gateway v1.14.3 // indirect
	github.com/h2non/go-is-svg v0.0.0-20160927212452-35e8c4b0612c
	github.com/jessevdk/go-flags v1.4.0
	github.com/jinzhu/gorm v1.9.10
	github.com/jrick/logrotate v1.0.0
	github.com/marcopeereboom/sbox v1.0.0
	github.com/otiai10/copy v1.0.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/robfig/cron v1.2.0
	github.com/subosito/gozaru v0.0.0-20190625071150-416082cce636
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.0.0-20190829043050-9756ffdc2472
	golang.org/x/net v0.0.0-20191028085509-fe3aa8a45271
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	google.golang.org/grpc v1.24.0
)

replace github.com/decred/politeia => github.com/thi4go/politeia v0.0.0-20200331190653-07de07497eb0
