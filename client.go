package libbtc

import (
	"context"
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
	// NetworkParams should return the network parameters of the underlying
	// Bitcoin blockchain.
	NetworkParams() *chaincfg.Params
	GetUnspentOutputs(ctx context.Context, address string, limit, confitmations int64) (Unspent, error)
	GetRawTransaction(ctx context.Context, txhash string) (Transaction, error)
	GetRawAddressInformation(ctx context.Context, addr string) (SingleAddress, error)

	// PublishTransaction should publish a signed transaction to the Bitcoin
	// blockchain.
	PublishTransaction(ctx context.Context, signedTransaction []byte) error

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
		panic(NewErrUnsupportedNetwork(network))
	}
}

func (client *client) GetUnspentOutputs(ctx context.Context, address string, limit, confitmations int64) (Unspent, error) {
	if limit == 0 {
		limit = 250
	}
	utxos := Unspent{}
	err := backoff(ctx, func() error {
		resp, err := http.Get(fmt.Sprintf("%s/unspent?active=%s&confirmations=%d&limit=%d", client.URL, address, confitmations, limit))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(respBytes) == "No free outputs to spend" {
			return nil
		}
		return json.Unmarshal(respBytes, &utxos)
	})
	return utxos, err
}

func (client *client) GetRawTransaction(ctx context.Context, txhash string) (Transaction, error) {
	transaction := Transaction{}
	err := backoff(ctx, func() error {
		resp, err := http.Get(fmt.Sprintf("%s/rawtx/%s", client.URL, txhash))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		txBytes, err := ioutil.ReadAll(resp.Body)
		return json.Unmarshal(txBytes, &transaction)
	})
	return transaction, err
}

func (client *client) GetRawAddressInformation(ctx context.Context, addr string) (SingleAddress, error) {
	addressInfo := SingleAddress{}
	err := backoff(ctx, func() error {
		resp, err := http.Get(fmt.Sprintf("%s/rawaddr/%s", client.URL, addr))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		addrBytes, err := ioutil.ReadAll(resp.Body)
		return json.Unmarshal(addrBytes, &addressInfo)
	})
	return addressInfo, err
}

func (client *client) PublishTransaction(ctx context.Context, signedTransaction []byte) error {
	data := url.Values{}
	data.Set("tx", hex.EncodeToString(signedTransaction))
	err := backoff(ctx, func() error {
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
			return NewErrBitcoinSubmitTx(stxResult)
		}
		return nil
	})
	return err
}

func (client *client) GetScriptFromSpentP2SH(ctx context.Context, address string) ([]byte, error) {
	for {
		addrInfo, err := client.GetRawAddressInformation(ctx, address)
		if err != nil {
			return nil, err
		}
		if addrInfo.Sent > 0 {
			break
		}
	}
	addrInfo, err := client.GetRawAddressInformation(ctx, address)
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

func (client *client) Balance(ctx context.Context, address string, confirmations int64) (balance int64, err error) {
	unspent, err := client.GetUnspentOutputs(ctx, address, 1000, confirmations)
	for _, utxo := range unspent.Outputs {
		balance = balance + utxo.Amount
	}
	return
}

func (client *client) ScriptSpent(ctx context.Context, address string) (bool, error) {
	rawAddress, err := client.GetRawAddressInformation(ctx, address)
	if err != nil {
		return false, err
	}
	return rawAddress.Sent > 0, nil
}

func (client *client) ScriptFunded(ctx context.Context, address string, value int64) (bool, int64, error) {
	rawAddress, err := client.GetRawAddressInformation(ctx, address)
	if err != nil {
		return false, 0, err
	}
	return rawAddress.Received >= value, rawAddress.Received, nil
}

func (client *client) NetworkParams() *chaincfg.Params {
	return client.Params
}

func (client *client) FormatTransactionView(msg, txhash string) string {
	switch client.NetworkParams().Name {
	case "mainnet":
		return fmt.Sprintf("%s, transaction can be viewed at https://www.blockchain.com/btc/tx/%s", msg, txhash)
	case "testnet3":
		return fmt.Sprintf("%s, transaction can be viewed at https://testnet.blockchain.info/tx/%s", msg, txhash)
	default:
		panic(NewErrUnsupportedNetwork(client.NetworkParams().Name))
	}
}

func backoff(ctx context.Context, f func() error) error {
	duration := time.Duration(1000)
	for {
		select {
		case <-ctx.Done():
			return ErrTimedOut
		default:
			err := f()
			if err == nil {
				return nil
			}
			fmt.Printf("Error: %v, will try again in %d sec\n", err, duration)
			time.Sleep(duration * time.Millisecond)
			duration = time.Duration(float64(duration) * 1.6)
		}
	}
}
