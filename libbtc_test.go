package libbtc_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/republicprotocol/libbtc-go"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
)

var _ = Describe("LibBTC", func() {
	loadMasterKey := func(network uint32) (*hdkeychain.ExtendedKey, error) {
		switch network {
		case 1:
			seed := bip39.NewSeed(os.Getenv("BITCOIN_TESTNET_MNEMONIC"), os.Getenv("BITCOIN_TESTNET_PASSPHRASE"))
			return hdkeychain.NewMaster(seed, &chaincfg.TestNet3Params)
		case 0:
			seed := bip39.NewSeed(os.Getenv("BITCOIN_MNEMONIC"), os.Getenv("BITCOIN_PASSPHRASE"))
			return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
		default:
			return nil, NewErrUnsupportedNetwork(fmt.Sprintf("network id: %d", network))
		}
	}

	loadKey := func(path ...uint32) (*ecdsa.PrivateKey, error) {
		key, err := loadMasterKey(path[1])
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

	getAccounts := func() (Account, Account) {
		client := NewBlockchainInfoClient("testnet")
		mainKey, err := loadKey(44, 1, 0, 0, 0) // "m/44'/1'/0'/0/0"
		Expect(err).Should(BeNil())
		mainAccount := NewAccount(client, mainKey)
		secKey, err := loadKey(44, 1, 1, 0, 0) // "m/44'/1'/1'/0/0"
		Expect(err).Should(BeNil())
		secondaryAccount := NewAccount(client, secKey)
		return mainAccount, secondaryAccount
	}

	getContractDetails := func(secret [32]byte) ([]byte, []byte, btcutil.Address) {
		secretHash := sha256.Sum256(secret[:])
		_, secondaryAccount := getAccounts()
		to, err := secondaryAccount.Address()
		Expect(err).Should(BeNil())
		contract, err := buildHaskLockContract(secretHash, to)
		Expect(err).Should(BeNil())
		contractAddress, err := btcutil.NewAddressScriptHash(contract, secondaryAccount.NetworkParams())
		Expect(err).Should(BeNil())
		payToContractPublicKey, err := txscript.PayToAddrScript(contractAddress)
		return contract, payToContractPublicKey, contractAddress
	}

	var secret [32]byte
	BeforeSuite(func() {
		rand.Read(secret[:])
	})

	Context("when interacting with testnet", func() {
		It("should get a valid address of an account", func() {
			mainAccount, _ := getAccounts()
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			Expect(addr.IsForNet(&chaincfg.TestNet3Params)).Should(BeTrue())
			fmt.Println("Address: ", addr)
		})

		It("should get correct network of an account", func() {
			mainAccount, _ := getAccounts()
			Expect(mainAccount.NetworkParams()).Should(Equal(&chaincfg.TestNet3Params))
		})

		It("should get a valid serialized public key of an account", func() {
			mainAccount, _ := getAccounts()
			pubKey, err := mainAccount.SerializedPublicKey()
			Expect(err).Should(BeNil())
			Expect(btcec.IsCompressedPubKey(pubKey)).Should(BeFalse())
			_, err = btcec.ParsePubKey(pubKey, btcec.S256())
			Expect(err).Should(BeNil())
		})

		It("should get the balance of an address", func() {
			mainAccount, _ := getAccounts()
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			balance, err := mainAccount.Balance(context.Background(), addr.String(), 0)
			Expect(err).Should(BeNil())
			fmt.Printf("%s: %d SAT", addr, balance)
		})

		It("should transfer 10000 SAT to another address", func() {
			mainAccount, secondaryAccount := getAccounts()
			secAddr, err := secondaryAccount.Address()
			Expect(err).Should(BeNil())
			initialBalance, err := secondaryAccount.Balance(context.Background(), secAddr.String(), 0)
			Expect(err).Should(BeNil())
			// building a transaction to transfer bitcoin to the secondary address
			_, err = mainAccount.Transfer(context.Background(), secAddr.String(), 10000)
			Expect(err).Should(BeNil())
			finalBalance, err := secondaryAccount.Balance(context.Background(), secAddr.String(), 0)
			Expect(err).Should(BeNil())
			Expect(finalBalance - initialBalance).Should(Equal(int64(10000)))
		})

		It("should deposit 50000 SAT to the contract address", func() {
			_, payToContractPublicKey, contractAddress := getContractDetails(secret)
			mainAccount, secondaryAccount := getAccounts()
			initialBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
			Expect(err).Should(BeNil())
			// building a transaction to transfer bitcoin to the secondary address
			err = mainAccount.SendTransaction(
				context.Background(),
				nil,
				10000, // fee
				nil,
				func(msgtx *wire.MsgTx) bool {
					funded, val, err := mainAccount.ScriptFunded(context.Background(), contractAddress.EncodeAddress(), 50000)
					if err != nil {
						return false
					}
					if !funded {
						msgtx.AddTxOut(wire.NewTxOut(50000-val, payToContractPublicKey))
					}
					return !funded
				},
				nil,
				func(msgtx *wire.MsgTx) bool {
					funded, _, err := mainAccount.ScriptFunded(context.Background(), contractAddress.EncodeAddress(), 50000)
					if err != nil {
						return false
					}
					return funded
				},
			)
			Expect(err).Should(BeNil())
			finalBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
			Expect(err).Should(BeNil())
			Expect(finalBalance - initialBalance).Should(Equal(int64(50000)))
		})

		It("should withdraw 50000 SAT from the contract address", func() {
			contract, _, contractAddress := getContractDetails(secret)
			_, secondaryAccount := getAccounts()
			initialBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
			Expect(err).Should(BeNil())
			secondaryAddress, err := secondaryAccount.Address()
			Expect(err).Should(BeNil())
			P2PKHScript, err := txscript.PayToAddrScript(secondaryAddress)
			Expect(err).Should(BeNil())
			// building a transaction to transfer bitcoin to the secondary address
			err = secondaryAccount.SendTransaction(
				context.Background(),
				contract,
				10000, // fee
				nil,
				func(msgtx *wire.MsgTx) bool {
					redeemed, val, err := secondaryAccount.ScriptRedeemed(context.Background(), contractAddress.EncodeAddress(), 50000)
					if err != nil {
						return false
					}
					if !redeemed {
						msgtx.AddTxOut(wire.NewTxOut(val-10000, P2PKHScript)) // value - fee
					}
					return !redeemed
				},
				func(builder *txscript.ScriptBuilder) {
					builder.AddData(secret[:])
				},
				func(msgtx *wire.MsgTx) bool {
					spent, err := secondaryAccount.ScriptSpent(context.Background(), contractAddress.EncodeAddress())
					if err != nil {
						return false
					}
					return spent
				},
			)
			Expect(err).Should(BeNil())
			finalBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
			Expect(err).Should(BeNil())
			Expect(initialBalance - finalBalance).Should(Equal(int64(50000)))
		})

		It("should be able to extract details from a spent contract", func() {
			_, _, contractAddress := getContractDetails(secret)
			mainAccount, _ := getAccounts()
			spent, err := mainAccount.ScriptSpent(context.Background(), contractAddress.EncodeAddress())
			Expect(err).Should(BeNil())
			Expect(spent).Should(BeTrue())
			sigScript, err := mainAccount.GetScriptFromSpentP2SH(context.Background(), contractAddress.EncodeAddress())
			Expect(err).Should(BeNil())
			pushes, err := txscript.PushedData(sigScript)
			Expect(err).Should(BeNil())
			success := false
			for _, push := range pushes {
				if bytes.Compare(push, secret[:]) == 0 {
					success = true
				}
			}
			Expect(success).Should(BeTrue())
		})
	})

})
