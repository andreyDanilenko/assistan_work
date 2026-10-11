package model_test

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"loki-analyzer/internal/model"
)

func TestParseOrderLogExample(t *testing.T) {
	body, err := os.ReadFile("../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data struct {
			Result []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}

	var logs []model.OrderLog
	var timestamps []int64
	for _, stream := range response.Data.Result {
		for _, value := range stream.Values {
			log, err := model.ParseOrderLog(value[1])
			if err != nil {
				t.Fatal(err)
			}
			if log.Level == nil || *log.Level != 30 || log.Context != "orders" {
				t.Fatal("expected numeric level 30 and orders context")
			}
			if log.TimeMS == nil {
				t.Fatal("missing application timestamp")
			}
			ns, err := strconv.ParseInt(value[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			logs = append(logs, log)
			timestamps = append(timestamps, ns)
		}
	}
	if len(logs) != 5 {
		t.Fatalf("got %d log lines, want 5", len(logs))
	}
	wantMessages := []string{
		"creating order", "create order item", "sending order to provision",
		"order created", "getting order",
	}
	for i, want := range wantMessages {
		if logs[i].Message != want {
			t.Errorf("line %d: unexpected message", i)
		}
	}
	order := logs[0]
	if order.ID != "71640535-1dd6-42b4-ae11-0137503455c0" || order.OrderID != "" {
		t.Fatal("order creation fields were not preserved")
	}
	if order.Type != "new" || len(order.Items) != 1 || order.Items[0].TariffID != "8ed2ad1b-478b-483e-9a0b-6abe9db922b5" {
		t.Fatal("order creation type or items were not preserved")
	}
	if order.OwnerID != "5b1f50aa-682b-42f4-920b-16076672422f" || order.ResellerID != "490a7b2f-2797-47be-ab24-b63dbc03edf8" {
		t.Fatal("order owner or reseller fields were not preserved")
	}
	if logs[1].ID != "386b2849-a8f3-476f-af99-f30370e25953" || logs[1].OrderID != order.ID {
		t.Fatal("item ID and parent order ID must remain separate")
	}
	if logs[2].Status != "provision" || logs[3].Status != "provision" {
		t.Fatal("provision status must be preserved without interpretation")
	}
	if string(order.EndTime) != "null" || logs[1].EndTime != nil {
		t.Fatal("explicit null and absent endTime must remain distinguishable")
	}
	if *order.TimeMS != 1791570347171 || timestamps[0] != 1791570347171964777 {
		t.Fatal("application milliseconds and Loki nanoseconds must remain exact")
	}
	if *logs[2].TimeMS == timestamps[2]/1_000_000 {
		t.Fatal("fixture must preserve differing application and Loki timestamps")
	}
}

func TestParseOrderLogOptionalAndUnknownFields(t *testing.T) {
	log, err := model.ParseOrderLog(` {"extra":{"newField":true}} `)
	if err != nil {
		t.Fatal(err)
	}
	if log.Level != nil || log.TimeMS != nil || log.Message != "" {
		t.Fatal("absent fields must remain unset")
	}
	log, err = model.ParseOrderLog(`{"level":0,"time":0}`)
	if err != nil || log.Level == nil || *log.Level != 0 || log.TimeMS == nil || *log.TimeMS != 0 {
		t.Fatal("explicit numeric zero must remain distinct from an absent field")
	}
	if _, err := model.ParseOrderLog(`{}`); err != nil {
		t.Fatal("parsing must not classify or reject objects without known fields")
	}
}

func TestParseOrderLogEndTimePreservesUnknownShape(t *testing.T) {
	for _, value := range []string{`null`, `1791570347171`, `"later"`, `{"value":1}`} {
		t.Run(value, func(t *testing.T) {
			log, err := model.ParseOrderLog(`{"endTime":` + value + `}`)
			if err != nil {
				t.Fatal(err)
			}
			if string(log.EndTime) != value {
				t.Fatal("endTime must retain its JSON representation")
			}
		})
	}
}

func TestParseOrderLogInvalidInputDoesNotExposeLogText(t *testing.T) {
	for _, input := range []string{
		"", "not JSON", "null", "[]", `"secret-value"`,
		`{"msg":"secret-value"`, `{"level":"secret-value"}`,
		`{"time":"secret-value"}`, `{"time":1.5}`, `{"msg":12}`,
		`{"items":[{"tariffId":42}]}`, `{} {"secret-value":1}`,
	} {
		_, err := model.ParseOrderLog(input)
		if err == nil {
			t.Fatal("expected invalid input to be rejected")
		}
		if strings.Contains(err.Error(), "secret-value") {
			t.Fatal("error exposes log text")
		}
	}
}
