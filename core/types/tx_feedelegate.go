package types

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	LegacyFeeDelegateTxType = 0x14 + iota
	AccessListFeeDelegateTxType
	DynamicFeeFeeDelegateTxType
)

func IsFeeDelegateTxType(ty byte) bool {
	return ty >= LegacyFeeDelegateTxType && ty <= DynamicFeeFeeDelegateTxType
}

func (tx *Transaction) OriginTx() *Transaction {
	if txData, ok := tx.inner.(FeeDelegateTxData); ok {
		return txData.origin()
	}
	return tx
}

func (tx *Transaction) From(s Signer) (common.Address, error) {
	if txData, ok := tx.inner.(FeeDelegateTxData); ok {
		return Sender(s, txData.origin())
	}
	return Sender(s, tx)
}

func (tx *Transaction) FeePayer(s Signer) (common.Address, error) {
	return Sender(s, tx)
}

func NewFeeDelegateTx(tx *Transaction) (*Transaction, error) {
	if IsFeeDelegateTxType(tx.Type()) {
		return tx, nil
	}

	// check is signed tx
	from, err := LatestSignerForChainID(tx.ChainId()).Sender(tx)
	if err != nil {
		return nil, err
	}
	if from == (common.Address{}) {
		return nil, errors.New("")
	}
	return NewTx(&FeeDelegateTx{Transaction: tx}), nil
}

type FeeDelegateTxData interface {
	TxData
	origin() *Transaction
}

type FeeDelegateTx struct {
	*Transaction
	V, R, S *big.Int
}

// for TxData
func (tx *FeeDelegateTx) txType() byte { return LegacyFeeDelegateTxType + tx.Transaction.Type() }
func (tx *FeeDelegateTx) copy() TxData {
	cpy := &FeeDelegateTx{
		Transaction: NewTx(tx.Transaction.inner),
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}
func (tx *FeeDelegateTx) chainID() *big.Int      { return tx.Transaction.inner.chainID() }
func (tx *FeeDelegateTx) accessList() AccessList { return tx.Transaction.inner.accessList() }
func (tx *FeeDelegateTx) data() []byte           { return tx.Transaction.inner.data() }
func (tx *FeeDelegateTx) gas() uint64            { return tx.Transaction.inner.gas() }
func (tx *FeeDelegateTx) gasPrice() *big.Int     { return tx.Transaction.inner.gasPrice() }
func (tx *FeeDelegateTx) gasFeeCap() *big.Int    { return tx.Transaction.inner.gasFeeCap() }
func (tx *FeeDelegateTx) gasTipCap() *big.Int    { return tx.Transaction.inner.gasTipCap() }
func (tx *FeeDelegateTx) value() *big.Int        { return tx.Transaction.inner.value() }
func (tx *FeeDelegateTx) nonce() uint64          { return tx.Transaction.inner.nonce() }
func (tx *FeeDelegateTx) to() *common.Address    { return tx.Transaction.inner.to() }
func (tx *FeeDelegateTx) rawSignatureValues() (v, r, s *big.Int) {
	v, r, s = tx.V, tx.R, tx.S
	return
}
func (tx *FeeDelegateTx) setSignatureValues(chainID, v, r, s *big.Int) {
	if chainID.Cmp(tx.Transaction.inner.chainID()) == 0 {
		tx.V, tx.R, tx.S = v, r, s
	}
}
func (tx *FeeDelegateTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return tx.Transaction.inner.effectiveGasPrice(dst, baseFee)
}

type feeDelegateTx struct {
	Transaction []byte
	V, R, S     *big.Int
}

func (tx *FeeDelegateTx) encode(b *bytes.Buffer) error {
	transaction, err := tx.Transaction.MarshalBinary()
	if err != nil {
		return err
	}
	return rlp.Encode(b, &feeDelegateTx{transaction, tx.V, tx.R, tx.S})
}

func (tx *FeeDelegateTx) decode(input []byte) error {
	var inner feeDelegateTx

	err := rlp.DecodeBytes(input, &inner)
	if err != nil {
		return err
	}

	tx.Transaction = new(Transaction)
	err = tx.Transaction.UnmarshalBinary(inner.Transaction)
	if err != nil {
		return err
	}

	if inner.V != nil {
		tx.V = inner.V
	}
	if inner.R != nil {
		tx.R = inner.R
	}
	if inner.S != nil {
		tx.S = inner.S
	}

	return nil
}

//////////////////////////////
// FeeDelegation Interfaces //
//////////////////////////////

func (tx *FeeDelegateTx) origin() *Transaction {
	return tx.Transaction
}
