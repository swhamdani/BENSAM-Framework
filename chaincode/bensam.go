package main

import (
	"encoding/json"
	"fmt"
	"time"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type LogRecord struct {
	LogHash   string `json:"logHash"`
	RefID     string `json:"refId"`
	Timestamp int64  `json:"timestamp"`
}

type BENSAMContract struct{ contractapi.Contract }

func (c *BENSAMContract) SubmitLog(ctx contractapi.TransactionContextInterface, hash, ref string) error {
	r := LogRecord{LogHash: hash, RefID: ref, Timestamp: time.Now().Unix()}
	data, _ := json.Marshal(r)
	return ctx.GetStub().PutState(ref, data)
}

func (c *BENSAMContract) QueryLog(ctx contractapi.TransactionContextInterface, ref string) (*LogRecord, error) {
	data, err := ctx.GetStub().GetState(ref)
	if err != nil || data == nil {
		return nil, fmt.Errorf("not found")
	}
	var rec LogRecord
	json.Unmarshal(data, &rec)
	return &rec, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&BENSAMContract{})
	if err != nil {
		panic(err)
	}
	chaincode.Start()
}
