package libbtc

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type tx struct {
	receiveValues   []int64
	scriptPublicKey []byte
	account         *account
	msgTx           *wire.MsgTx
	ctx             context.Context
}

func (account *account) newTx(ctx context.Context, msgtx *wire.MsgTx) *tx {
	return &tx{
		msgTx:   msgtx,
		account: account,
		ctx:     ctx,
	}
}

func (tx *tx) fund(addr btcutil.Address, fee int64) error {
	if addr == nil {
		var err error
		addr, err = tx.account.Address()
		if err != nil {
			return err
		}
	}

	var value int64
	for _, j := range tx.msgTx.TxOut {
		value = value + j.Value
	}
	value = value + fee

	balance, err := tx.account.Balance(tx.ctx, addr.EncodeAddress(), 0)
	if err != nil {
		return err
	}

	if value > balance {
		return NewErrInsufficientBalance(addr.EncodeAddress(), value, balance)
	}

	utxos, err := tx.account.GetUnspentOutputs(tx.ctx, addr.EncodeAddress(), 1000, 0)
	if err != nil {
		return err
	}
	for _, j := range utxos.Outputs {
		ScriptPubKey, err := hex.DecodeString(j.ScriptPubKey)
		if err != nil {
			return err
		}
		if len(tx.scriptPublicKey) == 0 {
			tx.scriptPublicKey = ScriptPubKey
		} else {
			if bytes.Compare(tx.scriptPublicKey, ScriptPubKey) != 0 {
				continue
			}
		}
		if value <= 0 {
			break
		}
		tx.receiveValues = append(tx.receiveValues, j.Amount)
		hashBytes, err := hex.DecodeString(j.TransactionHash)
		if err != nil {
			return err
		}
		hash, err := chainhash.NewHash(hashBytes)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(hash, j.TransactionOutputNumber), []byte{}, [][]byte{}))
		value = value - j.Amount
	}

	if value > 0 {
		return ErrMismatchedPubKeys
	}

	if value < 0 {
		P2PKHScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxOut(wire.NewTxOut(int64(-value), P2PKHScript))
	}

	return nil
}

func (tx *tx) sign(f func(*txscript.ScriptBuilder), contract []byte) error {
	var subScript []byte
	if contract == nil {
		subScript = tx.scriptPublicKey
	} else {
		subScript = contract
	}
	serializedPublicKey, err := tx.account.SerializedPublicKey()
	if err != nil {
		return err
	}
	for i, txin := range tx.msgTx.TxIn {
		sig, err := txscript.RawTxInSignature(tx.msgTx, i, subScript, txscript.SigHashAll, tx.account.PrivKey)
		if err != nil {
			return err
		}
		builder := txscript.NewScriptBuilder()
		builder.AddData(sig)
		builder.AddData(serializedPublicKey)
		if f != nil {
			f(builder)
		}
		if contract != nil {
			builder.AddData(contract)
		}
		sigScript, err := builder.Script()
		if err != nil {
			return err
		}
		txin.SignatureScript = sigScript
	}
	return nil
}

func (tx *tx) verify() error {
	for i, receiveValue := range tx.receiveValues {
		engine, err := txscript.NewEngine(tx.scriptPublicKey, tx.msgTx, i,
			txscript.StandardVerifyFlags, txscript.NewSigCache(10),
			txscript.NewTxSigHashes(tx.msgTx), receiveValue)
		if err != nil {
			return err
		}
		if err := engine.Execute(); err != nil {
			return err
		}
	}
	return nil
}

func (tx *tx) submit() error {
	var stxBuffer bytes.Buffer
	stxBuffer.Grow(tx.msgTx.SerializeSize())
	if err := tx.msgTx.Serialize(&stxBuffer); err != nil {
		return err
	}
	return tx.account.PublishTransaction(tx.ctx, stxBuffer.Bytes())
}
