package client

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
	"github.com/republicprotocol/libbtc-go"
)

type blockchainInfoClient struct {
	URL    string
	Params *chaincfg.Params
}

func NewBlockchainInfoClient(network string) libbtc.Client {
	network = strings.ToLower(network)
	switch network {
	case "mainnet":
		return &blockchainInfoClient{
			URL:    "https://blockchain.info",
			Params: &chaincfg.MainNetParams,
		}
	case "testnet", "testnet3", "":
		return &blockchainInfoClient{
			URL:    "https://testnet.blockchain.info",
			Params: &chaincfg.TestNet3Params,
		}
	default:
		panic(NewErrUnsupportedNetwork(network))
	}
}

func (client *blockchainInfoClient) GetUnspentOutputs(ctx context.Context, address string, limit, confitmations int64) (Unspent, error) {
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

func (client *blockchainInfoClient) GetRawAddressInformation(ctx context.Context, addr string) (SingleAddress, error) {
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

func (client *blockchainInfoClient) PublishTransaction(ctx context.Context, signedTransaction []byte) error {
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

func (client *blockchainInfoClient) NetworkParams() *chaincfg.Params {
	return client.Params
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
