package integration

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

func TestAttackPathStructure(t *testing.T) {
	// Test the PathStep and AttackPath structures directly
	pathStep := models.PathStep{
		Function:       "Unmarshal",
		Package:        "encoding/json",
		CallType:       "transitive",
		RiskIndicators: []string{"DESERIALIZATION"},
	}

	if pathStep.Function != "Unmarshal" {
		t.Errorf("Expected function 'Unmarshal', got %s", pathStep.Function)
	}

	if pathStep.Package != "encoding/json" {
		t.Errorf("Expected package 'encoding/json', got %s", pathStep.Package)
	}

	if pathStep.CallType != "transitive" {
		t.Errorf("Expected call type 'transitive', got %s", pathStep.CallType)
	}

	if len(pathStep.RiskIndicators) != 1 || pathStep.RiskIndicators[0] != "DESERIALIZATION" {
		t.Errorf("Expected risk indicators ['DESERIALIZATION'], got %v", pathStep.RiskIndicators)
	}

	// Test AttackPath structure
	attackPath := models.AttackPath{
		EntryFunction:    "processData",
		PathDepth:        2,
		RiskLevel:        "high",
		Path:             []models.PathStep{pathStep},
		VulnerabilityIDs: []string{"CVE-2023-1234"},
	}

	if attackPath.EntryFunction != "processData" {
		t.Errorf("Expected entry function 'processData', got %s", attackPath.EntryFunction)
	}

	if attackPath.PathDepth != 2 {
		t.Errorf("Expected path depth 2, got %d", attackPath.PathDepth)
	}

	if attackPath.RiskLevel != "high" {
		t.Errorf("Expected risk level 'high', got %s", attackPath.RiskLevel)
	}
}
