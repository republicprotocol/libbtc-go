package libbtc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

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
}

func (account *account) newTx(msgtx *wire.MsgTx) *tx {
	return &tx{
		msgTx:   msgtx,
		account: account,
	}
}

func (tx *tx) fund(scriptAddress btcutil.Address, fee int64) error {
	if scriptAddress == nil {
		return tx.fundFromAccount(fee)
	}
	return tx.fundFromScript(scriptAddress, fee)
}

func (tx *tx) sign(f func(*txscript.ScriptBuilder), script []byte) error {
	if script == nil {
		script = tx.scriptPublicKey
	}
	for i, txin := range tx.msgTx.TxIn {
		sig, err := txscript.RawTxInSignature(tx.msgTx, i, script, txscript.SigHashAll, tx.account.PrivKey)
		if err != nil {
			return err
		}
		builder := txscript.NewScriptBuilder()
		builder.AddData(sig)
		builder.AddData(tx.account.PubKey)
		if f != nil {
			f(builder)
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
		e, err := txscript.NewEngine(tx.scriptPublicKey, tx.msgTx, i,
			txscript.StandardVerifyFlags, txscript.NewSigCache(10),
			txscript.NewTxSigHashes(tx.msgTx), receiveValue)
		if err != nil {
			return err
		}
		if err := e.Execute(); err != nil {
			return err
		}
	}
	return nil
}

func (tx *tx) submit(postCon func(*wire.MsgTx) bool) error {
	var stxBuffer bytes.Buffer
	stxBuffer.Grow(tx.msgTx.SerializeSize())
	if err := tx.msgTx.Serialize(&stxBuffer); err != nil {
		return err
	}
	for {
		if err := tx.account.PublishTransaction(stxBuffer.Bytes()); err != nil {
			return err
		}
		if postCon == nil {
			return nil
		}
		for i := 0; i < 20; i++ {
			if postCon(tx.msgTx) {
				return nil
			}
			time.Sleep(15 * time.Second)
		}
	}
}

func (tx *tx) fundFromAccount(fee int64) error {
	var value int64
	for _, j := range tx.msgTx.TxOut {
		value = value + j.Value
	}
	value = value + fee
	addr, err := tx.account.Address()
	if err != nil {
		return err
	}
	unspentValue := tx.account.Balance(addr.EncodeAddress(), 0)
	if value > unspentValue {
		return fmt.Errorf("Not enough balance in %s "+
			"required:%d current:%d", addr.EncodeAddress(), value, unspentValue)
	}
	utxos := tx.account.GetUnspentOutputs(addr.EncodeAddress(), 1000, 0)
	for _, j := range utxos.Outputs {
		ScriptPubKey, err := hex.DecodeString(j.ScriptPubKey)
		if err != nil {
			return err
		}
		if bytes.Compare(tx.scriptPublicKey, []byte{}) == 0 {
			tx.scriptPublicKey = ScriptPubKey
		} else {
			if bytes.Compare(tx.scriptPublicKey, ScriptPubKey) != 0 {
				continue
			}
		}
		tx.receiveValues = append(tx.receiveValues, j.Amount)
		if value <= 0 {
			break
		}
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

	if value < 0 {
		P2PKHScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxOut(wire.NewTxOut(int64(-value), P2PKHScript))
	}
	if value > 0 {
		return fmt.Errorf("Failed to fund the transaction mismatched script public keys")
	}
	return nil
}

func (tx *tx) fundFromScript(scriptAddress btcutil.Address, fee int64) error {
	utxos := tx.account.GetUnspentOutputs(scriptAddress.EncodeAddress(), 1000, 0)
	for _, j := range utxos.Outputs {
		ScriptPubKey, err := hex.DecodeString(j.ScriptPubKey)
		if err != nil {
			return err
		}
		if bytes.Compare(tx.scriptPublicKey, []byte{}) == 0 {
			tx.scriptPublicKey = ScriptPubKey
		} else {
			if bytes.Compare(tx.scriptPublicKey, ScriptPubKey) != 0 {
				continue
			}
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
	}
	return nil
}
