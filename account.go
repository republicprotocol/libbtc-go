package libbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type account struct {
	PrivKey *btcec.PrivateKey
	Client
}

type Client interface {
	// NetworkParams should return the network parameters of the underlying
	// Bitcoin blockchain.
	NetworkParams() *chaincfg.Params
	GetUnspentOutputs(ctx context.Context, address string, limit, confitmations int64) (Unspent, error)
	// GetRawTransaction(ctx context.Context, txhash string) (Transaction, error)
	GetRawAddressInformation(ctx context.Context, addr string) (SingleAddress, error)

	// PublishTransaction should publish a signed transaction to the Bitcoin
	// blockchain.
	PublishTransaction(ctx context.Context, signedTransaction []byte) error
}

// Account is an Bitcoin external account that can sign and submit transactions
// to the Bitcoin blockchain. An Account is an abstraction over the Bitcoin
// blockchain.
type Account interface {
	Client
	Address() (btcutil.Address, error)
	SerializedPublicKey() ([]byte, error)
	Transfer(ctx context.Context, to string, value int64) error
	SendTransaction(
		ctx context.Context,
		script []byte,
		fee int64,
		preCond func(*wire.MsgTx) bool,
		f func(*txscript.ScriptBuilder),
		postCond func(*wire.MsgTx) bool,
	) error

	// Balance of the given address on Bitcoin blockchain.
	Balance(ctx context.Context, address string, confirmations int64) (int64, error)

	// ScriptSpent checks whether a script is spent.
	ScriptSpent(ctx context.Context, address string) (bool, error)

	// ScriptFunded checks whether a script is funded.
	ScriptFunded(ctx context.Context, address string, value int64) (bool, int64, error)
	GetScriptFromSpentP2SH(ctx context.Context, address string) ([]byte, error)

	// FormatTransactionView formats the message and txhash into a user friendly
	// message.
	FormatTransactionView(msg, txhash string) string
}

// NewAccount returns a user account for the provided private key which is
// connected to a Bitcoin client.
func NewAccount(client Client, privateKey *ecdsa.PrivateKey) Account {
	return &account{
		(*btcec.PrivateKey)(privateKey),
		client,
	}
}

// Address returns the address of the given private key
func (account *account) Address() (btcutil.Address, error) {
	pubKeyBytes, err := account.SerializedPublicKey()
	if err != nil {
		return nil, err
	}
	pubKey, err := btcutil.NewAddressPubKey(pubKeyBytes, account.NetworkParams())
	if err != nil {
		return nil, err
	}
	addrString := pubKey.EncodeAddress()
	return btcutil.DecodeAddress(addrString, account.NetworkParams())
}

// Transfer bitcoins to the given address
func (account *account) Transfer(ctx context.Context, to string, value int64) error {
	address, err := btcutil.DecodeAddress(to, account.NetworkParams())
	if err != nil {
		return err
	}
	return account.SendTransaction(
		ctx,
		nil,
		1000,
		func(tx *wire.MsgTx) bool {
			P2PKHScript, err := txscript.PayToAddrScript(address)
			if err != nil {
				return false
			}
			tx.AddTxOut(wire.NewTxOut(value, P2PKHScript))
			return true
		},
		nil,
		nil,
	)
}

// SendTransaction builds, signs, verifies and publishes a transaction to the
// corresponding blockchain. If contract is provided then the transaction uses
// the contract's unspent outputs for the transaction, otherwise uses the
// account's unspent outputs to fund the transaction. preCond is executed in
// the starting of the process, if it returns false SendTransaction returns
// ErrPreConditionCheckFailed and stops the process. This function can be used
// to modify how the unspent outputs are spent, this can be nil. f is supposed
// to be used with non empty contracts, to modify the signature script. preCond
// is executed in the starting of the process, if it returns false
// SendTransaction returns ErrPreConditionCheckFailed and stops the process.
func (account *account) SendTransaction(
	ctx context.Context,
	contract []byte,
	fee int64,
	preCond func(*wire.MsgTx) bool,
	f func(*txscript.ScriptBuilder),
	postCond func(*wire.MsgTx) bool,
) error {
	// Current Bitcoin Transaction Version (2).
	tx := account.newTx(ctx, wire.NewMsgTx(2))
	if preCond != nil && !preCond(tx.msgTx) {
		return ErrPreConditionCheckFailed
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

	for {
		select {
		case <-ctx.Done():
			return ErrPostConditionCheckFailed
		default:
			if err := tx.submit(); err != nil {
				return err
			}
			for i := 0; i < 60; i++ {
				if postCond == nil || postCond(tx.msgTx) {
					return nil
				}
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (account *account) GetScriptFromSpentP2SH(ctx context.Context, address string) ([]byte, error) {
	for {
		addrInfo, err := account.GetRawAddressInformation(ctx, address)
		if err != nil {
			return nil, err
		}
		if addrInfo.Sent > 0 {
			break
		}
	}
	addrInfo, err := account.GetRawAddressInformation(ctx, address)
	if err != nil {
		return nil, err
	}
	for _, tx := range addrInfo.Transactions {
		for i := range tx.Inputs {
			if tx.Inputs[i].PrevOut.Address == addrInfo.Address {
				return hex.DecodeString(tx.Inputs[i].Script)
			}
		}
	}
	return nil, ErrNoSpendingTransactions
}

func (account *account) Balance(ctx context.Context, address string, confirmations int64) (balance int64, err error) {
	unspent, err := account.GetUnspentOutputs(ctx, address, 1000, confirmations)
	for _, utxo := range unspent.Outputs {
		balance = balance + utxo.Amount
	}
	return
}

func (account *account) ScriptSpent(ctx context.Context, address string) (bool, error) {
	rawAddress, err := account.GetRawAddressInformation(ctx, address)
	if err != nil {
		return false, err
	}
	return rawAddress.Sent > 0, nil
}

func (account *account) ScriptFunded(ctx context.Context, address string, value int64) (bool, int64, error) {
	rawAddress, err := account.GetRawAddressInformation(ctx, address)
	if err != nil {
		return false, 0, err
	}
	return rawAddress.Received >= value, rawAddress.Received, nil
}

func (account *account) FormatTransactionView(msg, txhash string) string {
	switch account.NetworkParams().Name {
	case "mainnet":
		return fmt.Sprintf("%s, transaction can be viewed at https://www.blockchain.com/btc/tx/%s", msg, txhash)
	case "testnet3":
		return fmt.Sprintf("%s, transaction can be viewed at https://testnet.blockchain.info/tx/%s", msg, txhash)
	default:
		panic(NewErrUnsupportedNetwork(account.NetworkParams().Name))
	}
}

func (account *account) SerializedPublicKey() ([]byte, error) {
	pubKey := account.PrivKey.PubKey()
	switch account.NetworkParams() {
	case &chaincfg.MainNetParams:
		return pubKey.SerializeCompressed(), nil
	case &chaincfg.TestNet3Params:
		return pubKey.SerializeUncompressed(), nil
	default:
		return nil, NewErrUnsupportedNetwork(account.NetworkParams().Name)
	}
}
