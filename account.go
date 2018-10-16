package libbtc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
)

// ErrPreConditionCheckFailed indicates that the pre-condition for executing
// a transaction failed.
var ErrPreConditionCheckFailed = errors.New("pre-condition check failed")

// ErrPostConditionCheckFailed indicates that the post-condition for executing
// a transaction failed.
var ErrPostConditionCheckFailed = errors.New("post-condition check failed")

type account struct {
	PrivKey *btcec.PrivateKey
	PubKey  []byte
	Client
}

// Account is an Bitcoin external account that can sign and submit transactions
// to the Bitcoin blockchain. An Account is an abstraction over the Bitcoin
// blockchain.
type Account interface {
	Client
	Address() (btcutil.Address, error)
	SerializedPublicKey() []byte
	SendTransaction(
		script []byte,
		fee int64,
		f func(*txscript.ScriptBuilder),
		preCon, postCon func(*wire.MsgTx) bool,
	) error
}

// NewAccount returns a user account for the provided private key which is
// connected to a Bitcoin client.
func NewAccount(client Client, privateKey *ecdsa.PrivateKey) Account {
	privKey := (*btcec.PrivateKey)(privateKey)
	pubKey := privKey.PubKey()
	switch client.NetworkParams() {
	case &chaincfg.MainNetParams:
		return &account{
			privKey,
			pubKey.SerializeCompressed(),
			client,
		}
	case &chaincfg.TestNet3Params:
		return &account{
			privKey,
			pubKey.SerializeUncompressed(),
			client,
		}
	default:
		panic(fmt.Errorf("Unsupported network: %s", client.NetworkParams().Name))
	}
}

// Address returns the address of the given private key
func (account *account) Address() (btcutil.Address, error) {
	pubKey, err := btcutil.NewAddressPubKey(account.PubKey, account.NetworkParams())
	if err != nil {
		return nil, err
	}
	addrString := pubKey.EncodeAddress()
	return btcutil.DecodeAddress(addrString, account.NetworkParams())
}

// SendTransaction builds, signs, verifies and publishes a transaction to the
// corresponding blockchain.
func (account *account) SendTransaction(
	// when trying to receive bitcoins from a contract, provide the contract
	// data, otherwise can be nil.
	contract []byte,
	// fee for the transaction
	fee int64,
	// If you need to add data to the signature script, implement this function
	// and add data. signature, publickey and the script are embedded by default.
	f func(*txscript.ScriptBuilder),
	// preCon is executed in the starting of the process, returns
	// ErrPreConditionCheckFailed and stops the process.
	// postCon is executed after submitting the transaction to the blockchain,
	// returns ErrPostConditionCheckFailed if postCon returns false.
	preCon, postCon func(*wire.MsgTx) bool,
) error {
	tx := account.newTx(wire.NewMsgTx(2))
	if preCon != nil {
		if !preCon(tx.msgTx) {
			return ErrPreConditionCheckFailed
		}
	}
	var address btcutil.Address
	var err error
	if contract == nil {
		address, err = account.Address()
		if err != nil {
			return err
		}
	} else {
		address, err = btcutil.NewAddressScriptHash(contract, account.NetworkParams())
		if err != nil {
			return err
		}
	}
	if err := tx.fund(address, fee); err != nil {
		return err
	}
	if err := tx.sign(f, contract); err != nil {
		return err
	}
	if err := tx.verify(); err != nil {
		return err
	}
	if err := tx.submit(); err != nil {
		return err
	}
	if postCon != nil {
		if !postCon(tx.msgTx) {
			return ErrPostConditionCheckFailed
		}
	}
	return nil
}

func (account *account) SerializedPublicKey() []byte {
	return account.PubKey
}
