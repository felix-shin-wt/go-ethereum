package types_test

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func TestLegacyFeeDelegateTxType(t *testing.T) {
	initTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nonce, err := backend.Client().PendingNonceAt(ctx, spender.address)
	require.NoError(t, err)
	gasPrice, err := backend.Client().SuggestGasPrice(ctx)
	require.NoError(t, err)
	originTx1 := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &receiver.address,
		Value:    new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:      1e6,
		GasPrice: gasPrice,
	})
	originTx1, err = types.SignTx(originTx1, signer, spender.pk)
	require.NoError(t, err)
	require.NoError(t, backend.Client().SendTransaction(ctx, originTx1))
	backend.Commit()
	receipt, err := bind.WaitMined(ctx, backend.Client(), originTx1)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	beforeSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)

	gasPrice, err = backend.Client().SuggestGasPrice(ctx)
	require.NoError(t, err)

	originTx2 := types.NewTx(&types.LegacyTx{
		Nonce:    nonce + 1,
		To:       &receiver.address,
		Value:    new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:      1e6,
		GasPrice: gasPrice,
	})
	_, err = types.NewFeeDelegateTx(originTx2)
	require.Error(t, err)

	originTx2, err = types.SignTx(originTx2, signer, spender.pk)
	require.NoError(t, err)

	feeDelegateTx, err := types.NewFeeDelegateTx(originTx2)
	require.NoError(t, err)

	feeDelegateTx, err = types.SignTx(feeDelegateTx, signer, feePayer.pk)
	require.NoError(t, err)

	t.Run("Check JSON", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalJSON()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalJSON(bytes1))

		bytes2, err := tempTx.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	t.Run("Check Binary", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalBinary()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalBinary(bytes1))

		bytes2, err := tempTx.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	beforeFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	require.NoError(t, backend.Client().SendTransaction(ctx, feeDelegateTx))
	backend.Commit()

	receipt, err = bind.WaitMined(ctx, backend.Client(), feeDelegateTx)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	afterSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)
	afterFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	gasUsed := new(big.Int).Mul(feeDelegateTx.GasPrice(), big.NewInt(int64(receipt.GasUsed)))
	require.Equal(t, gasUsed, new(big.Int).Sub(beforeFeePayerBalance, afterFeePayerBalance))
	require.Equal(t, originTx2.Value(), new(big.Int).Sub(beforeSpenderBalance, afterSpenderBalance))
}

func TestAccessListFeeDelegateTxType(t *testing.T) {
	initTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nonce, err := backend.Client().PendingNonceAt(ctx, spender.address)
	require.NoError(t, err)
	gasPrice, err := backend.Client().SuggestGasPrice(ctx)
	require.NoError(t, err)
	originTx1 := types.NewTx(&types.AccessListTx{
		Nonce:    nonce,
		To:       &receiver.address,
		Value:    new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:      1e6,
		GasPrice: gasPrice,
	})
	originTx1, err = types.SignTx(originTx1, signer, spender.pk)
	require.NoError(t, err)
	require.NoError(t, backend.Client().SendTransaction(ctx, originTx1))
	backend.Commit()
	receipt, err := bind.WaitMined(ctx, backend.Client(), originTx1)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	beforeSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)

	gasPrice, err = backend.Client().SuggestGasPrice(ctx)
	require.NoError(t, err)

	originTx2 := types.NewTx(&types.AccessListTx{
		Nonce:    nonce + 1,
		To:       &receiver.address,
		Value:    new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:      1e6,
		GasPrice: gasPrice,
	})
	_, err = types.NewFeeDelegateTx(originTx2)
	require.Error(t, err)

	originTx2, err = types.SignTx(originTx2, signer, spender.pk)
	require.NoError(t, err)

	feeDelegateTx, err := types.NewFeeDelegateTx(originTx2)
	require.NoError(t, err)

	feeDelegateTx, err = types.SignTx(feeDelegateTx, signer, feePayer.pk)
	require.NoError(t, err)

	t.Run("Check JSON", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalJSON()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalJSON(bytes1))

		bytes2, err := tempTx.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	t.Run("Check Binary", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalBinary()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalBinary(bytes1))

		bytes2, err := tempTx.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	beforeFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	require.NoError(t, backend.Client().SendTransaction(ctx, feeDelegateTx))
	backend.Commit()

	receipt, err = bind.WaitMined(ctx, backend.Client(), feeDelegateTx)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	afterSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)
	afterFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	gasUsed := new(big.Int).Mul(feeDelegateTx.GasPrice(), big.NewInt(int64(receipt.GasUsed)))
	require.Equal(t, gasUsed, new(big.Int).Sub(beforeFeePayerBalance, afterFeePayerBalance))
	require.Equal(t, originTx2.Value(), new(big.Int).Sub(beforeSpenderBalance, afterSpenderBalance))
}
func TestDynamicFeeFeeDelegateTxType(t *testing.T) {
	initTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nonce, err := backend.Client().PendingNonceAt(ctx, spender.address)
	require.NoError(t, err)

	header, err := backend.Client().HeaderByNumber(ctx, nil)
	require.NoError(t, err)
	baseFee := header.BaseFee
	require.True(t, baseFee.Sign() > 0)
	gasTipCap, err := backend.Client().SuggestGasTipCap(ctx)
	require.NoError(t, err)
	originTx1 := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		To:        &receiver.address,
		Value:     new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:       1e6,
		GasTipCap: gasTipCap,
		GasFeeCap: new(big.Int).Add(gasTipCap, new(big.Int).Mul(big.NewInt(2), baseFee)),
	})
	originTx1, err = types.SignTx(originTx1, signer, spender.pk)
	require.NoError(t, err)
	require.NoError(t, backend.Client().SendTransaction(ctx, originTx1))
	backend.Commit()
	receipt, err := bind.WaitMined(ctx, backend.Client(), originTx1)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	beforeSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)

	header, err = backend.Client().HeaderByNumber(ctx, nil)
	require.NoError(t, err)
	baseFee = header.BaseFee
	require.True(t, baseFee.Sign() > 0)
	gasTipCap, err = backend.Client().SuggestGasTipCap(ctx)
	require.NoError(t, err)
	originTx2 := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce + 1,
		To:        &receiver.address,
		Value:     new(big.Int).Mul(common.Big1, big.NewInt(params.Ether)),
		Gas:       1e6,
		GasTipCap: gasTipCap,
		GasFeeCap: new(big.Int).Add(gasTipCap, new(big.Int).Mul(big.NewInt(2), baseFee)),
	})
	_, err = types.NewFeeDelegateTx(originTx2)
	require.Error(t, err)

	originTx2, err = types.SignTx(originTx2, signer, spender.pk)
	require.NoError(t, err)

	feeDelegateTx, err := types.NewFeeDelegateTx(originTx2)
	require.NoError(t, err)

	feeDelegateTx, err = types.SignTx(feeDelegateTx, signer, feePayer.pk)
	require.NoError(t, err)

	t.Run("Check JSON", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalJSON()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalJSON(bytes1))

		bytes2, err := tempTx.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	t.Run("Check Binary", func(t *testing.T) {
		bytes1, err := feeDelegateTx.MarshalBinary()
		require.NoError(t, err)

		tempTx := new(types.Transaction)
		require.NoError(t, tempTx.UnmarshalBinary(bytes1))

		bytes2, err := tempTx.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2)
	})

	beforeFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	require.NoError(t, backend.Client().SendTransaction(ctx, feeDelegateTx))
	backend.Commit()

	receipt, err = bind.WaitMined(ctx, backend.Client(), feeDelegateTx)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	afterSpenderBalance, err := backend.Client().PendingBalanceAt(ctx, spender.address)
	require.NoError(t, err)
	afterFeePayerBalance, err := backend.Client().PendingBalanceAt(ctx, feePayer.address)
	require.NoError(t, err)

	require.Equal(t, originTx2.Value(), new(big.Int).Sub(beforeSpenderBalance, afterSpenderBalance))
	feepaied := new(big.Int).Sub(beforeFeePayerBalance, afterFeePayerBalance)
	gasPrice, err := backend.Client().SuggestGasPrice(ctx)
	require.NoError(t, err)
	legacyGasUsed := new(big.Int).Mul(gasPrice, big.NewInt(int64(receipt.GasUsed)))
	require.True(t, legacyGasUsed.Cmp(feepaied) >= 0)
}

var (
	backend  *simulated.Backend
	signer   types.Signer
	spender  *eoa
	receiver *eoa
	feePayer *eoa
)

type eoa struct {
	address common.Address
	pk      *ecdsa.PrivateKey
}

func newEOA(t *testing.T) *eoa {
	pk, err := crypto.GenerateKey()
	require.NoError(t, err)
	return &eoa{crypto.PubkeyToAddress(pk.PublicKey), pk}
}

func initTest(t *testing.T) {
	if backend != nil {
		return
	}
	// log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelTrace, true)))
	spender = newEOA(t)
	receiver = newEOA(t)
	feePayer = newEOA(t)
	backend = simulated.NewBackend(types.GenesisAlloc{
		spender.address:  {Balance: new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))},
		feePayer.address: {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.Ether))},
	},
		simulated.WithBlockGasLimit(params.MaxGasLimit),
		simulated.WithCallGasLimit(params.MaxGasLimit),
		simulated.WithMinerMinTip(common.Big1),
		func(nodeConf *node.Config, ethConf *ethconfig.Config) {
			ethConf.Genesis.Config.PangyoBlock = common.Big0
			ethConf.Genesis.Config.ApplepieBlock = common.Big0
			ethConf.Genesis.Config.BriocheBlock = common.Big0
		},
	)
	chainID, err := backend.Client().ChainID(context.TODO())
	require.NoError(t, err)

	signer = types.LatestSignerForChainID(chainID)
}
