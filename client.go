package libbtc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

type PreviousOut struct {
	TransactionHash  string `json:"hash"`
	Value            uint64 `json:"value"`
	TransactionIndex uint64 `json:"tx_index"`
	VoutNumber       uint8  `json:"n"`
	Address          string `json:"addr"`
}

type Input struct {
	PrevOut PreviousOut `json:"prev_out"`
	Script  string      `json:"script"`
}

type Output struct {
	Value           uint64 `json:"value"`
	TransactionHash string `json:"hash"`
	Script          string `json:"script"`
}

type Transaction struct {
	TransactionHash  string   `json:"hash"`
	Version          uint8    `json:"ver"`
	VinSize          uint32   `json:"vin_sz"`
	VoutSize         uint32   `json:"vout_sz"`
	Size             int64    `json:"size"`
	RelayedBy        string   `json:"relayed_by"`
	BlockHeight      int64    `json:"block_height"`
	TransactionIndex uint64   `json:"tx_index"`
	Inputs           []Input  `json:"inputs"`
	Outputs          []Output `json:"out"`
}

type Block struct {
	BlockHash         string        `json:"hash"`
	Version           uint8         `json:"ver"`
	PreviousBlockHash string        `json:"prev_block"`
	MerkleRoot        string        `json:"mrkl_root"`
	Time              int64         `json:"time"`
	Bits              int64         `json:"bits"`
	Nonce             int64         `json:"nonce"`
	TransactionCount  int           `json:"n_tx"`
	Size              int64         `json:"size"`
	BlockIndex        uint64        `json:"block_index"`
	MainChain         bool          `json:"main_chain"`
	Height            int64         `json:"height"`
	ReceivedTime      int64         `json:"received_time"`
	RelayedBy         string        `json:"relayed_by"`
	Transactions      []Transaction `json:"tx"`
}

type Blocks struct {
	Blocks []Block `json:"block"`
}

type SingleAddress struct {
	PublicKeyHash              string        `json:"hash160"`
	Address                    string        `json:"address"`
	TransactionCount           int64         `json:"n_tx"`
	UnredeemedTransactionCount int64         `json:"n_unredeemed"`
	Received                   int64         `json:"total_received"`
	Sent                       int64         `json:"total_sent"`
	Balance                    int64         `json:"final_balance"`
	Transactions               []Transaction `json:"txs"`
}

type Address struct {
	PublicKeyHash    string `json:"hash160"`
	Address          string `json:"address"`
	TransactionCount int64  `json:"n_tx"`
	Received         int64  `json:"total_received"`
	Sent             int64  `json:"total_sent"`
	Balance          int64  `json:"final_balance"`
}

type MultiAddress struct {
	Addresses    []Address     `json:"addresses"`
	Transactions []Transaction `json:"txs"`
}

type UnspentOutput struct {
	TransactionAge          string `json:"tx_age"`
	TransactionHash         string `json:"tx_hash"`
	TransactionIndex        uint32 `json:"tx_index"`
	TransactionOutputNumber uint32 `json:"tx_output_n"`
	ScriptPubKey            string `json:"script"`
	Amount                  int64  `json:"value"`
}

type Unspent struct {
	Outputs []UnspentOutput `json:"unspent_outputs"`
}

type client struct {
	URL    string
	Params *chaincfg.Params
}

type Client interface {
	NetworkParams() *chaincfg.Params
	GetUnspentOutputs(address string, limit, confitmations int64) Unspent
	GetRawTransaction(txhash string) Transaction
	GetRawAddressInformation(addr string) SingleAddress
	PublishTransaction(signedTransaction []byte) error
	Balance(address string, confirmations int64) int64
	ScriptSpent(address string) bool
	ScriptFunded(address string, value int64) (bool, int64)
	GetScriptFromSpentP2SH(address string) ([]byte, error)
}

func NewBlockchainInfoClient(network string) Client {
	network = strings.ToLower(network)
	switch network {
	case "mainnet":
		return &client{
			URL:    "https://blockchain.info",
			Params: &chaincfg.MainNetParams,
		}
	case "testnet", "testnet3", "":
		return &client{
			URL:    "https://testnet.blockchain.info",
			Params: &chaincfg.TestNet3Params,
		}
	default:
		panic(fmt.Sprintf("Unknown Network %s", network))
	}
}

func (client *client) GetUnspentOutputs(address string, limit, confitmations int64) Unspent {
	if limit == 0 {
		limit = 250
	}
	for {
		resp, err := http.Get(fmt.Sprintf("%s/unspent?active=%s&confirmations=%d&limit=%d", client.URL, address, confitmations, limit))
		if err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		defer resp.Body.Close()
		utxoBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		if string(utxoBytes) == "No free outputs to spend" {
			return Unspent{
				Outputs: []UnspentOutput{},
			}
		}
		utxos := Unspent{}
		if err := json.Unmarshal(utxoBytes, &utxos); err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		return utxos
	}
}

func (client *client) GetRawTransaction(txhash string) Transaction {
	for {
		resp, err := http.Get(fmt.Sprintf("%s/rawtx/%s", client.URL, txhash))
		if err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		defer resp.Body.Close()
		txBytes, err := ioutil.ReadAll(resp.Body)
		transaction := Transaction{}
		if err := json.Unmarshal(txBytes, &transaction); err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		return transaction
	}
}

func (client *client) GetRawAddressInformation(addr string) SingleAddress {
	for {
		resp, err := http.Get(fmt.Sprintf("%s/rawaddr/%s", client.URL, addr))
		if err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		defer resp.Body.Close()
		addrBytes, err := ioutil.ReadAll(resp.Body)
		addressInfo := SingleAddress{}
		if err := json.Unmarshal(addrBytes, &addressInfo); err != nil {
			fmt.Println(err, " will try again in 10 sec")
			time.Sleep(10 * time.Second)
			continue
		}
		return addressInfo
	}
}

func (client *client) PublishTransaction(signedTransaction []byte) error {
	data := url.Values{}
	data.Set("tx", hex.EncodeToString(signedTransaction))
	httpClient := &http.Client{}
	r, err := http.NewRequest("POST", fmt.Sprintf("%s/pushtx", client.URL), strings.NewReader(data.Encode())) // URL-encoded payload
	if err != nil {
		return err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	stxResultBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	stxResult := string(stxResultBytes)

	if !strings.Contains(stxResult, "Transaction Submitted") {
		return fmt.Errorf("Error while submitting Bitcoin transaction: %s", stxResult)
	}
	return nil
}

func (client *client) GetScriptFromSpentP2SH(address string) ([]byte, error) {
	for {
		addrInfo := client.GetRawAddressInformation(address)
		if addrInfo.Sent > 0 {
			break
		}
	}
	addrInfo := client.GetRawAddressInformation(address)
	for _, tx := range addrInfo.Transactions {
		for i := range tx.Inputs {
			if tx.Inputs[i].PrevOut.Address == addrInfo.Address {
				return hex.DecodeString(tx.Inputs[i].Script)
			}
		}
	}
	return nil, fmt.Errorf("No spending transactions")
}

func (client *client) Balance(address string, confirmations int64) int64 {
	unspent := client.GetUnspentOutputs(address, 1000, confirmations)
	var balance int64
	for _, utxo := range unspent.Outputs {
		balance = balance + utxo.Amount
	}
	return balance
}

func (client *client) ScriptSpent(address string) bool {
	rawAddress := client.GetRawAddressInformation(address)
	return rawAddress.Sent > 0
}

func (client *client) ScriptFunded(address string, value int64) (bool, int64) {
	rawAddress := client.GetRawAddressInformation(address)
	return rawAddress.Received >= value, rawAddress.Received
}

func (client *client) NetworkParams() *chaincfg.Params {
	return client.Params
}
