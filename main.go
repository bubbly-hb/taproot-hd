package main

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"log"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"strconv"
)

func main() {
	// 从种子创建主密钥
	seed := []byte("your_secure_random_seed")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}

	// 定义 BIP84 派生路径
	bip84DerivationPath := "m/84'/0'/0'"

	// 派生 BIP84 子密钥
	child, err := deriveChildKey(master, bip84DerivationPath)
	if err != nil {
		log.Fatal(err)
	}

	// 获取 P2TR 地址
	p2trAddr, err := getP2TRAddressFromKey(child)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("P2TR Address:", p2trAddr)
}

// getP2TRAddressFromKey 获取 P2TR 地址
func getP2TRAddressFromKey(key *hdkeychain.ExtendedKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}

	tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)
	address, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams,
	)
	if err != nil {
		return "", err
	}
	return address.EncodeAddress(), nil
}

// getP2WPKHAddressFromKey 获取 P2WPKH 地址
func getP2WPKHAddressFromKey(key *hdkeychain.ExtendedKey) (btcutil.Address, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	// 创建 P2WPKH 地址
	addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// 派生子密钥的辅助函数
func deriveChildKey(parent *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
	// 按照派生路径派生子密钥
	parts := strings.Split(path, "/")
	for _, part := range parts[1:] {
		indexStr := strings.TrimSuffix(part, "'")

		index, err := strconv.ParseUint(indexStr, 10, 32)
		if err != nil {
			return nil, err
		}

		// 创建硬化或非硬化索引
		child, err := parent.Derive(uint32(index))
		if err != nil {
			return nil, err
		}

		// 更新父密钥为当前派生的子密钥
		parent = child
	}

	return parent, nil
}
