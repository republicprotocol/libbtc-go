package libbtc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
)

var ErrPreconditionCheckFailed = errors.New("Precondition Check Failed")

type account struct {
	Network *chaincfg.Params
	PrivKey *btcec.PrivateKey
	PubKey  []byte
	Client
}

type Account interface {
	Client
	Address() (btcutil.Address, error)
	SerializedPublicKey() []byte
	Net() *chaincfg.Params
	SendTransaction(
		msgtx *wire.MsgTx,
		scriptAddress btcutil.Address,
		script []byte,
		fee int64,
		f func(*txscript.ScriptBuilder),
		preCon, postCon func(*wire.MsgTx) bool,
	) error
}

// NewAccount returns a user account for the provided private key which is
// connected to a Bitcoin client.
func NewAccount(network string, privateKey *ecdsa.PrivateKey) (Account, error) {
	privKey := (*btcec.PrivateKey)(privateKey)
	pubKey := privKey.PubKey()
	network = strings.ToLower(network)
	switch network {
	case "mainnet", "":
		return &account{
			&chaincfg.MainNetParams,
			privKey,
			pubKey.SerializeCompressed(),
			Connect("https://blockchain.info"),
		}, nil
	case "testnet", "testnet3":
		return &account{
			&chaincfg.TestNet3Params,
			privKey,
			pubKey.SerializeUncompressed(),
			Connect("https://testnet.blockchain.info"),
		}, nil
	default:
		return nil, fmt.Errorf("Unknown network: %s", network)
	}
}

func (account *account) Address() (btcutil.Address, error) {
	pubKey, err := btcutil.NewAddressPubKey(account.PubKey, account.Network)
	if err != nil {
		return nil, err
	}
	addrString := pubKey.EncodeAddress()
	return btcutil.DecodeAddress(addrString, account.Network)
}

func (account *account) SendTransaction(
	msgtx *wire.MsgTx,
	scriptAddress btcutil.Address,
	script []byte,
	fee int64,
	f func(*txscript.ScriptBuilder),
	preCon, postCon func(*wire.MsgTx) bool,
) error {
	tx := account.newTx(msgtx)
	if preCon != nil {
		if !preCon(tx.msgTx) {
			return ErrPreconditionCheckFailed
		}
	}
	if err := tx.fund(scriptAddress, fee); err != nil {
		return err
	}
	if err := tx.sign(f, script); err != nil {
		return err
	}
	if err := tx.verify(); err != nil {
		return err
	}
	return tx.submit(postCon)
}

func (account *account) SerializedPublicKey() []byte {
	return account.PubKey
}

func (account *account) Net() *chaincfg.Params {
	return account.Network
}
