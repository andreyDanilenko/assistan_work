package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// LogRecord хранит исходное событие с доступными метками и metadata.
// Line остается без изменений; одинаковые записи пока считаются отдельными событиями.
type LogRecord struct {
	Timestamp time.Time
	Project   string
	Line      string
	Labels    map[string]string
	Metadata  map[string]string
}

// Response объединяет исходный ответ и разобранные данные: Query для логов, Values для меток.
// Body может содержать персональные данные и секреты из логов.
type Response struct {
	Body       json.RawMessage
	StatusCode int
	Truncated  bool
	Query      *LokiQueryResponse
	Values     []string
}

// FetchResult отличает пустой успешный результат от неполной загрузки периода.
// Complete относится к доступным данным Loki: запоздавшие события могут появиться позже.
type FetchResult struct {
	Records   []LogRecord
	Complete  bool
	Reason    string
	Requests  int
	BytesRead int64
}

// LokiQueryResponse описывает JSON-ответ query_range отдельно от общей модели LogRecord.
type LokiQueryResponse struct {
	Status string        `json:"status"`
	Data   LokiQueryData `json:"data"`
}

// LokiQueryData содержит потоки событий и диагностику выполнения запроса.
type LokiQueryData struct {
	ResultType string          `json:"resultType"`
	Result     []LokiStream    `json:"result"`
	Stats      json.RawMessage `json:"stats,omitempty"` // Статистика запроса, а не события заказов.
}

// LokiStream объединяет события с одинаковым набором меток; имена меток не фиксированы.
type LokiStream struct {
	Labels map[string]string `json:"stream"`
	Values []LokiEntry       `json:"values"`
}

// LokiEntry соответствует массиву ["timestamp_ns", "line", необязательные metadata].
// Line остается текстом: сообщение сервиса может содержать JSON или обычную строку.
type LokiEntry struct {
	TimestampNS int64
	Line        string
	Metadata    map[string]string
}

// UnmarshalJSON проверяет формат массива и читает наносекунды без округления.
func (entry *LokiEntry) UnmarshalJSON(data []byte) error {
	var tuple []json.RawMessage
	if json.Unmarshal(data, &tuple) != nil || (len(tuple) != 2 && len(tuple) != 3) {
		return errors.New("invalid Loki log entry")
	}
	// Время и сообщение должны быть строками: JSON null здесь недопустим.
	stampJSON := bytes.TrimSpace(tuple[0])
	if len(stampJSON) == 0 || stampJSON[0] != '"' {
		return errors.New("invalid Loki log entry values")
	}
	lineJSON := bytes.TrimSpace(tuple[1])
	if len(lineJSON) == 0 || lineJSON[0] != '"' {
		return errors.New("invalid Loki log entry values")
	}
	var timestamp, line string
	if json.Unmarshal(stampJSON, &timestamp) != nil || json.Unmarshal(lineJSON, &line) != nil {
		return errors.New("invalid Loki log entry values")
	}
	// Прямое преобразование в int64 сохраняет точность, которую потерял бы float64.
	ns, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(ns, 10) != timestamp {
		return errors.New("invalid Loki timestamp")
	}
	var metadata map[string]string
	if len(tuple) == 3 {
		if json.Unmarshal(tuple[2], &metadata) != nil || metadata == nil {
			return errors.New("invalid Loki structured metadata")
		}
	}
	// Обновляем запись только после полной проверки, сбрасывая прежние metadata.
	*entry = LokiEntry{TimestampNS: ns, Line: line, Metadata: metadata}
	return nil
}

// MarshalJSON сохраняет формат массива Loki и строковое представление наносекунд.
func (entry LokiEntry) MarshalJSON() ([]byte, error) {
	tuple := []any{strconv.FormatInt(entry.TimestampNS, 10), entry.Line}
	if entry.Metadata != nil {
		tuple = append(tuple, entry.Metadata)
	}
	return json.Marshal(tuple)
}
