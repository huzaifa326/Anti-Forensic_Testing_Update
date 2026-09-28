package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Smart Contract Definition
type EvidenceChaincode struct {
	contractapi.Contract
}

// Evidence Asset representation
type Evidence struct {
	ArtifactID   string `json:"artifact_id"`
	Hash         string `json:"sha256_hash"`
	Metadata     string `json:"metadata"`
	Timestamp    string `json:"timestamp"`
	Investigator string `json:"investigator"`
}

// RecordEvidence initializes a new evidence entry on the ledger
func (c *EvidenceChaincode) RecordEvidence(ctx contractapi.TransactionContextInterface, artifactID string, hash string, metadata string, timestamp string, investigator string) error {
	exists, err := c.EvidenceExists(ctx, artifactID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("evidence record for artifact %s already exists in chain of custody", artifactID)
	}

	evidence := Evidence{
		ArtifactID:   artifactID,
		Hash:         hash,
		Metadata:     metadata,
		Timestamp:    timestamp,
		Investigator: investigator,
	}

	assetJSON, err := json.Marshal(evidence)
	if err != nil {
		return err
	}

	// Committing to the indelible ledger
	return ctx.GetStub().PutState(artifactID, assetJSON)
}

// VerifyEvidence pulls the evidence from ledger and confirms the matching hash
func (c *EvidenceChaincode) VerifyEvidence(ctx contractapi.TransactionContextInterface, artifactID string, providedHash string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(artifactID)
	if err != nil {
		return false, fmt.Errorf("failed to read artifact from world state: %v", err)
	}
	if assetJSON == nil {
		return false, fmt.Errorf("evidence artifact %s does not exist", artifactID)
	}

	var evidence Evidence
	err = json.Unmarshal(assetJSON, &evidence)
	if err != nil {
		return false, err
	}

	// Validate integrity
	if evidence.Hash == providedHash {
		return true, nil
	}

	return false, nil
}

// EvidenceExists checks if evidence exists on the ledger
func (c *EvidenceChaincode) EvidenceExists(ctx contractapi.TransactionContextInterface, artifactID string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(artifactID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&EvidenceChaincode{})
	if err != nil {
		fmt.Printf("Error spawning evidence chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting evidence chaincode sequence: %v\n", err)
	}
}
