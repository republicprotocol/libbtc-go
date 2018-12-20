package client

import (
	"errors"
	"fmt"
)

var ErrTimedOut = errors.New("timed out")

var ErrNoSpendingTransactions = fmt.Errorf("No spending transactions")

var ErrMismatchedPubKeys = fmt.Errorf("failed to fund the transaction mismatched script public keys")

func NewErrUnsupportedNetwork(network string) error {
	return fmt.Errorf("unsupported network %s", network)
}

func NewErrBitcoinSubmitTx(msg string) error {
	return fmt.Errorf("error while submitting Bitcoin transaction: %s", msg)
}
func NewErrInsufficientBalance(address string, required, current int64) error {
	return fmt.Errorf("insufficient balance in %s "+
		"required:%d current:%d", address, required, current)
}
