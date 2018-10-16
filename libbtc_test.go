package libbtc_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/btcsuite/btcd/btcec"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/btcsuite/btcutil/hdkeychain"
	bip39 "github.com/tyler-smith/go-bip39"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/republicprotocol/libbtc-go"
)

type Keys struct {
	Testnet Key `json:"testnet"`
	Mainnet Key `json:"mainnet"`
}

type Key struct {
	Mnemonic string `json:"mnemonic"`
	Password string `json:"password"`
}

var _ = Describe("", func() {
	loadMasterKey := func(network uint32) (*hdkeychain.ExtendedKey, error) {
		keys := Keys{}
		keysBytes, err := ioutil.ReadFile("secrets/keys.json")
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(keysBytes, &keys); err != nil {
			return nil, err
		}
		switch network {
		case 1:
			seed := bip39.NewSeed(keys.Testnet.Mnemonic, keys.Testnet.Password)
			return hdkeychain.NewMaster(seed, &chaincfg.TestNet3Params)
		case 0:
			seed := bip39.NewSeed(keys.Mainnet.Mnemonic, keys.Mainnet.Password)
			return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
		default:
			return nil, fmt.Errorf("Unsupported bitcoin network %d", network)
		}
	}

	loadKey := func(path ...uint32) (*ecdsa.PrivateKey, error) {
		key, err := loadMasterKey(1)
		if err != nil {
			return nil, err
		}
		for _, val := range path {
			key, err = key.Child(val)
			if err != nil {
				return nil, err
			}
		}
		privKey, err := key.ECPrivKey()
		if err != nil {
			return nil, err
		}
		return privKey.ToECDSA(), nil
	}

	buildHaskLockContract := func(secretHash [32]byte, to btcutil.Address) ([]byte, error) {
		b := txscript.NewScriptBuilder()
		b.AddOp(txscript.OP_SIZE)
		b.AddData([]byte{32})
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_SHA256)
		b.AddData(secretHash[:])
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_DUP)
		b.AddOp(txscript.OP_HASH160)
		b.AddData(to.(*btcutil.AddressPubKeyHash).Hash160()[:])
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_CHECKSIG)
		return b.Script()
	}

	var mainAccount, secondaryAccount Account
	var secret, secretHash [32]byte
	var contract, payToContractPublicKey []byte
	var contractAddress string
	BeforeSuite(func() {
		mainKey, err := loadKey(44, 1, 0, 0, 0) // "m/44'/1'/0'/0/0"
		Expect(err).Should(BeNil())
		mainAccount, err = NewAccount("testnet", mainKey)
		Expect(err).Should(BeNil())
		secKey, err := loadKey(44, 1, 1, 0, 0) // "m/44'/1'/1'/0/0"
		Expect(err).Should(BeNil())
		secondaryAccount, err = NewAccount("testnet", secKey)
		Expect(err).Should(BeNil())
		rand.Read(secret[:])
		secretHash = sha256.Sum256(secret[:])
		to, err := secondaryAccount.Address()
		Expect(err).Should(BeNil())
		contract, err = buildHaskLockContract(secretHash, to)
		Expect(err).Should(BeNil())
		contractP2SH, err := btcutil.NewAddressScriptHash(contract, &chaincfg.TestNet3Params)
		Expect(err).Should(BeNil())
		payToContractPublicKey, err = txscript.PayToAddrScript(contractP2SH)
		Expect(err).Should(BeNil())
		contractAddress = contractP2SH.EncodeAddress()
	})

	Context("when interacting with testnet", func() {
		It("should get a valid address of an account", func() {
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			Expect(addr.IsForNet(&chaincfg.TestNet3Params)).Should(BeTrue())
			fmt.Println("Address: ", addr)
		})

		It("should get correct network of an account", func() {
			Expect(mainAccount.Net()).Should(Equal(&chaincfg.TestNet3Params))
		})

		It("should get a valid serialized public key of an account", func() {
			pubKey := mainAccount.SerializedPublicKey()
			Expect(btcec.IsCompressedPubKey(pubKey)).Should(BeFalse())
			_, err := btcec.ParsePubKey(pubKey, btcec.S256())
			Expect(err).Should(BeNil())
		})

		It("should get the balance of an address", func() {
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			balance := mainAccount.Balance(addr.String(), 0)
			fmt.Printf("%s: %d SAT", addr, balance)
		})

		It("should transfer 10000 SAT to another address", func() {
			secAddr, err := secondaryAccount.Address()
			Expect(err).Should(BeNil())
			initialBalance := secondaryAccount.Balance(secAddr.String(), 0)
			// building a transaction to transfer bitcoin to the secondary address
			tx := wire.NewMsgTx(2)
			P2PKHScript, err := txscript.PayToAddrScript(secAddr)
			Expect(err).Should(BeNil())
			tx.AddTxOut(wire.NewTxOut(10000, P2PKHScript))
			err = mainAccount.SendTransaction(
				tx,
				nil,
				nil,
				10000, // fee
				nil,
				nil,
				nil,
			)
			Expect(err).Should(BeNil())
			finalBalance := secondaryAccount.Balance(secAddr.String(), 0)
			Expect(finalBalance - initialBalance).Should(Equal(int64(10000)))
		})
	})

	Context("when interacting with a contract on testnet", func() {

		It("should deposit 50000 SAT to the contract address", func() {
			initialBalance := secondaryAccount.Balance(contractAddress, 0)
			// building a transaction to transfer bitcoin to the secondary address
			tx := wire.NewMsgTx(2)
			err := mainAccount.SendTransaction(
				tx,
				nil,
				nil,
				10000, // fee
				nil,
				func(msgtx *wire.MsgTx) bool {
					funded, val := mainAccount.ScriptFunded(contractAddress, 50000)
					if !funded {
						msgtx.AddTxOut(wire.NewTxOut(50000-val, payToContractPublicKey))
					}
					return !funded
				},
				func(msgtx *wire.MsgTx) bool {
					funded, _ := mainAccount.ScriptFunded(contractAddress, 50000)
					return funded
				},
			)
			Expect(err).Should(BeNil())
			finalBalance := secondaryAccount.Balance(contractAddress, 0)
			Expect(finalBalance - initialBalance).Should(Equal(int64(50000)))
		})

		It("should withdraw 50000 SAT from the contract address", func() {
			initialBalance := secondaryAccount.Balance(contractAddress, 0)
			contractAddr, err := btcutil.DecodeAddress(contractAddress, secondaryAccount.Net())
			Expect(err).Should(BeNil())
			secondaryAddress, err := secondaryAccount.Address()
			Expect(err).Should(BeNil())
			P2PKHScript, err := txscript.PayToAddrScript(secondaryAddress)
			Expect(err).Should(BeNil())

			// building a transaction to transfer bitcoin to the secondary address
			tx := wire.NewMsgTx(2)
			err = secondaryAccount.SendTransaction(
				tx,
				contractAddr,
				contract,
				10000, // fee
				func(builder *txscript.ScriptBuilder) {
					builder.AddData(secret[:])
					builder.AddData(contract)
				},
				func(msgtx *wire.MsgTx) bool {
					funded, val := mainAccount.ScriptFunded(contractAddress, 50000)
					if funded {
						msgtx.AddTxOut(wire.NewTxOut(val-10000, P2PKHScript)) // value - fee
					}
					return funded
				},
				func(msgtx *wire.MsgTx) bool {
					return mainAccount.ScriptSpent(contractAddress)
				},
			)
			Expect(err).Should(BeNil())
			finalBalance := secondaryAccount.Balance(contractAddress, 0)
			Expect(initialBalance - finalBalance).Should(Equal(int64(50000)))
		})
	})
})
