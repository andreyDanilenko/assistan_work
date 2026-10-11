package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var contextID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// LookupResellers дополняет контекст заказа из сохранённых 48 часов до End.
// Start относится к самому отчёту: история не добавляет в него события и счётчики.
// Возвращаем все найденные ID, чтобы разные реселлеры не превращались в случайный выбор.
func LookupResellers(ctx context.Context, path string, query Query, orderIDs []string) (map[string][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if query.Project == "" || query.SourceID == "" || !query.Start.Before(query.End) || query.End.Sub(query.Start) > Retention {
		return nil, errors.New("для поиска реселлеров нужны источник, проект и период до 48 часов")
	}
	start := query.End.Add(-Retention)
	for _, at := range []time.Time{start, query.Start, query.End} {
		if !time.Unix(0, at.UnixNano()).Equal(at) {
			return nil, errors.New("время поиска реселлеров не помещается в наносекунды Unix")
		}
	}
	if len(orderIDs) > 100000 {
		return nil, errors.New("поиск реселлеров превышает 100000 заказов")
	}
	wanted := make(map[string]bool, len(orderIDs))
	for _, id := range orderIDs {
		if !contextID.MatchString(id) {
			return nil, errors.New("для поиска реселлера нужен безопасный ID заказа")
		}
		wanted[id] = true
	}
	if len(wanted) == 0 {
		return map[string][]string{}, nil
	}
	// Только существующая база своего формата; открытие не создаёт файл и не меняет права.
	if strings.TrimSpace(path) == "" || path == ":memory:" || strings.HasPrefix(strings.ToLower(path), "file:") || strings.ContainsRune(path, 0) {
		return nil, errors.New("для SQLite нужен обычный путь к файлу")
	}
	filename, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("не удалось определить путь SQLite")
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("SQLite должен быть существующим обычным файлом")
	}
	address := url.URL{Scheme: "file", Path: filepath.ToSlash(filename)}
	address.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)", "trusted_schema(OFF)", "query_only(ON)"}}.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, safeError(ctx, "не удалось открыть SQLite для поиска реселлеров")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	fresh, err := inspectSchema(ctx, db)
	if err != nil {
		return nil, err
	}
	if fresh {
		return nil, errors.New("в файле нет базы логов")
	}
	// Читаем по одной строке; кратность одинаковых событий для связи заказа не нужна.
	// Пределы не позволяют запросу истории бесконтрольно занимать память и время.
	const maxRows, maxBytes = 2000000, 512 << 20
	rows, err := db.QueryContext(ctx, `SELECT length(CAST(raw_line AS BLOB)),
 CASE WHEN length(CAST(raw_line AS BLOB)) <= ? THEN raw_line ELSE '' END
 FROM log_events WHERE source_id = ? AND project = ? AND timestamp_ns >= ? AND timestamp_ns < ? LIMIT ?`,
		maxBytes, query.SourceID, query.Project, start.UnixNano(), query.End.UnixNano(), maxRows+1)
	if err != nil {
		return nil, safeError(ctx, "не удалось прочитать историю реселлеров")
	}
	defer rows.Close()
	found := make(map[string]map[string]bool)
	count, bytes := 0, int64(0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var line string
		var size int64
		if err := rows.Scan(&size, &line); err != nil {
			return nil, safeError(ctx, "не удалось прочитать связь заказа и реселлера")
		}
		count++
		bytes += size
		if count > maxRows || bytes > maxBytes || size < 0 {
			return nil, errors.New("история реселлеров превышает 2000000 строк или 512 МиБ; неполные связи не используются")
		}
		order, reseller := recordReseller(line)
		if !wanted[order] || !contextID.MatchString(reseller) {
			continue
		}
		if found[order] == nil {
			found[order] = make(map[string]bool)
		}
		found[order][reseller] = true
	}
	if err := rows.Err(); err != nil {
		return nil, safeError(ctx, "не удалось завершить поиск реселлеров")
	}
	result := make(map[string][]string, len(found))
	for order, resellers := range found {
		for reseller := range resellers {
			result[order] = append(result[order], reseller)
		}
		sort.Strings(result[order])
	}
	return result, nil
}

// Отдельное поле orderId имеет приоритет. Простое id считаем заказом только
// у известных событий orders, иначе это может быть ID позиции или другого объекта.
func recordReseller(line string) (string, string) {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(line), &fields) != nil {
		return "", ""
	}
	value := func(keys ...string) string {
		for _, key := range keys {
			var text string
			if json.Unmarshal(fields[key], &text) == nil && text != "" {
				return text
			}
		}
		return ""
	}
	order := value("orderId", "order_id")
	if order == "" && value("context") == "orders" {
		switch value("msg", "message") {
		case "creating order", "sending order to provision", "order created", "getting order", "order received successfully", "checking order exists":
			order = value("id")
		}
	}
	return order, value("resellerId", "reseller_id")
}
