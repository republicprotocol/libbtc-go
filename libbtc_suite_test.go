package libbtc_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLibbtc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Libbtc Suite")
}
