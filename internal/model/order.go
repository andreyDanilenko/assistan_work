package model

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// OrderLog описывает известные поля JSON-сообщения sds-orders без оценки результата заказа.
// Поля могут отсутствовать; неизвестные поля остаются только в исходной LogRecord.Line.
type OrderLog struct {
	Level      *int            `json:"level,omitempty"`
	TimeMS     *int64          `json:"time,omitempty"` // Unix-миллисекунды приложения, не наносекунды Loki.
	Context    string          `json:"context,omitempty"`
	ID         string          `json:"id,omitempty"` // ID заказа или его позиции, зависит от сообщения.
	OrderID    string          `json:"orderId,omitempty"`
	Type       string          `json:"type,omitempty"`
	Items      []OrderItem     `json:"items,omitempty"`
	OwnerID    string          `json:"ownerId,omitempty"`
	ResellerID string          `json:"resellerId,omitempty"`
	EndTime    json.RawMessage `json:"endTime,omitempty"` // Пока наблюдался только null; тип значения не предполагаем.
	Status     string          `json:"status,omitempty"`
	Message    string          `json:"msg,omitempty"`
}

// OrderItem содержит известные поля позиции из сообщения о создании заказа.
type OrderItem struct {
	TariffID string `json:"tariffId,omitempty"`
}

// ParseOrderLog разбирает JSON-объект; распознавание бизнес-события выполняет analyzer.
// Объект без известных полей допустим. Ошибки не включают исходный текст лога.
func ParseOrderLog(line string) (OrderLog, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return OrderLog{}, errors.New("order log must be a JSON object")
	}

	var log OrderLog
	if err := json.Unmarshal([]byte(line), &log); err != nil {
		return OrderLog{}, errors.New("order log contains invalid JSON or field types")
	}
	return log, nil
}

// OrderStatus отражает только вывод по наблюдаемым событиям текущей выборки.
type OrderStatus string

const (
	OrderUnknown     OrderStatus = "unknown"
	OrderInProgress  OrderStatus = "in_progress"
	OrderProvisioned OrderStatus = "provisioned" // Подтвержден этап обработки, не весь бизнес-процесс.
	OrderSucceeded   OrderStatus = "succeeded"   // Зарезервировано: текущие правила не присваивают.
	OrderFailed      OrderStatus = "failed"      // Зарезервировано: ошибка операции не означает падение заказа.
)

// OrderEvent содержит распознанные поля без исходного текста, меток pod и сервера.
// ResellerID взят из этого события; общая принадлежность заказа определяется в OrderState.
type OrderEvent struct {
	Project           string    `json:"project"`
	OrderID           string    `json:"order_id"`
	ItemID            string    `json:"item_id,omitempty"`
	ResellerID        string    `json:"reseller_id,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
	Type              string    `json:"type"`
	SourceStatus      string    `json:"source_status,omitempty"`
	Level             *int      `json:"level,omitempty"`
	ApplicationTimeMS *int64    `json:"application_time_ms,omitempty"`
	IsError           bool      `json:"is_error"`
}

// OrderState — сводка и история одного заказа в проекте в пределах загруженной выборки.
// Разные ResellerID дают ResellerConflict; пропуски истории здесь не восстанавливаются.
type OrderState struct {
	Project          string       `json:"project"`
	OrderID          string       `json:"order_id"`
	ResellerID       string       `json:"reseller_id,omitempty"`
	State            OrderStatus  `json:"state"`
	SourceStatus     string       `json:"source_status,omitempty"`
	FirstSeen        time.Time    `json:"first_seen"`
	LastSeen         time.Time    `json:"last_seen"`
	Events           []OrderEvent `json:"events"`
	ErrorCount       int          `json:"error_count"`
	ResellerConflict bool         `json:"reseller_conflict"`
}

// AnalysisResult объединяет истории заказов, сводки и счетчики причин пропуска строк.
// SyntheticRecords учитывает только записи с явной меткой учебного набора.
type AnalysisResult struct {
	TotalRecords     int               `json:"total_records"`
	SyntheticRecords int               `json:"synthetic_records"`
	Orders           []OrderState      `json:"orders"`
	Skipped          map[string]int    `json:"skipped"`
	ErrorEvents      int               `json:"error_events"`
	Resellers        []ResellerSummary `json:"resellers"`
}

// ResellerSummary считает заказы и ошибки операций отдельно в пределах проекта.
// Пустой ResellerID означает неизвестную или противоречивую принадлежность.
type ResellerSummary struct {
	Project     string `json:"project"`
	ResellerID  string `json:"reseller_id"`
	Orders      int    `json:"orders"`
	InProgress  int    `json:"in_progress"`
	Provisioned int    `json:"provisioned"`
	Unknown     int    `json:"unknown"`
	Succeeded   int    `json:"succeeded"`
	Failed      int    `json:"failed"`
	ErrorEvents int    `json:"error_events"`
}
