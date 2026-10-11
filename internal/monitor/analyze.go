package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"loki-analyzer/internal/model"
)

// Filter применяется к исходным строкам только в памяти; nil Include/Exclude отключает фильтр.
// При nil Critical используются слова fatal/critical в сообщении или текстовом уровне.
type Filter struct{ Include, Exclude, Critical *regexp.Regexp }

// Issue — безопасная сводка ошибки операции, а не конечный исход заказа.
// Pod и Server относятся к последнему событию группы с устойчивым выбором при равном времени.
type Issue struct {
	Key              string    `json:"key"`
	Kind             string    `json:"kind"`
	OrderID          string    `json:"order_id,omitempty"`
	OrderType        string    `json:"order_type"`
	ResellerID       string    `json:"reseller_id,omitempty"`
	ResellerConflict bool      `json:"reseller_conflict,omitempty"`
	Pod              string    `json:"pod,omitempty"`
	Server           string    `json:"server,omitempty"`
	Count            int       `json:"count"`
	Critical         bool      `json:"critical"`
	First            time.Time `json:"first"`
	Last             time.Time `json:"last"`
}

type OrderCounts struct {
	Type       string `json:"type"`
	Total      int    `json:"total"`
	Succeeded  int    `json:"succeeded"`
	WithErrors int    `json:"with_errors"`
	Other      int    `json:"other"`
}

type Snapshot struct {
	Coverage           model.Coverage `json:"coverage"`
	Total              int            `json:"total"`
	Orders             int            `json:"orders"`
	OrdersWithErrors   int            `json:"orders_with_errors"`
	OrdersSucceeded    int            `json:"orders_succeeded"`
	OrdersOther        int            `json:"orders_other"`
	Errors             int            `json:"errors"`
	ErrorsWithoutOrder int            `json:"errors_without_order"`
	Filtered           int            `json:"filtered"`
	Issues             []Issue        `json:"issues"`
	ByType             []OrderCounts  `json:"by_type"`
	resolvedBefore     map[string]time.Time
}

// CoverageText отделяет полноту сохранённого периода от результатов заказов.
// Короткое сообщение ограничивает только перечень пробелов; TXT перечисляет их все.
func (s Snapshot) CoverageText() string {
	if !s.Coverage.Known {
		return "⚪ Полнота сбора за период не подтверждена.\n"
	}
	if len(s.Coverage.Gaps) == 0 {
		return "✅ Все участки периода получены из Loki. Поздние логи могут дополнить результат.\n"
	}
	var out strings.Builder
	out.WriteString("⚠️ Неполный сбор. Счётчики только по сохранённым данным.\n")
	for _, gap := range s.Coverage.Gaps[:min(3, len(s.Coverage.Gaps))] {
		fmt.Fprintf(&out, "Не подтверждено: %s — %s UTC\n", gap.Start.UTC().Format("02.01 15:04:05"), gap.End.UTC().Format("02.01 15:04:05"))
	}
	if len(s.Coverage.Gaps) > 3 {
		fmt.Fprintf(&out, "Ещё неподтверждённых участков: %d. Все границы — в TXT.\n", len(s.Coverage.Gaps)-3)
	}
	return out.String()
}

// IsResolved также проверяет сохранённые ошибки, которых уже нет в текущем окне.
func (s Snapshot) IsResolved(issue Issue) bool {
	if issue.Kind == "order_create_error_still_provisioning" {
		return true
	}
	confirmed, ok := s.resolvedBefore[issue.Key]
	return ok && issue.Last.Before(confirmed)
}

var errorWord = regexp.MustCompile(`(?i)\b(error|fatal|critical)\b`)
var criticalWord = regexp.MustCompile(`(?i)\b(fatal|critical)\b`)
var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var safeInfrastructure = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

type parsedRecord struct {
	message, level, order, orderType, reseller, pod, server, kind string
	provisioned, critical                                         bool
}

// Analyze считает все заказы до фильтров, а ошибки и заказы с ошибками — после них.
// Заказ учитывается один раз на проект; одинаковые записи ошибок сохраняют кратность.
// Связь с реселлером берется из всего окна только при отсутствии противоречий.
func Analyze(records []model.LogRecord, filter Filter) Snapshot {
	result := Snapshot{Total: len(records), Issues: []Issue{}, ByType: []OrderCounts{}, resolvedBefore: make(map[string]time.Time)}
	parsed := make([]parsedRecord, len(records))
	type orderKey struct{ project, order string }
	orders := make(map[orderKey]struct{})
	ordersWithErrors := make(map[orderKey]struct{})
	provisioned := make(map[orderKey]time.Time)
	latestErrors := make(map[orderKey]time.Time)
	orderTypes := make(map[orderKey]string)
	typeConflicts := make(map[orderKey]bool)
	resellers := make(map[orderKey]string)
	conflicts := make(map[orderKey]bool)
	for index, record := range records {
		entry := parseRecord(record)
		entry.critical = criticalWord.MatchString(entry.message) || criticalWord.MatchString(entry.level)
		if filter.Critical != nil {
			entry.critical = filter.Critical.MatchString(record.Line)
		}
		if entry.kind == "" && (errorWord.MatchString(entry.message) || errorLevel(entry.level) || entry.critical) {
			entry.kind = "other_error"
		}
		parsed[index] = entry
		key := orderKey{record.Project, entry.order}
		if entry.order != "" {
			orders[key] = struct{}{}
			if entry.orderType != "" {
				if previous := orderTypes[key]; previous != "" && previous != entry.orderType {
					typeConflicts[key] = true
				}
				orderTypes[key] = entry.orderType
			}
			when := record.Timestamp.UTC()
			if previous, ok := provisioned[key]; entry.provisioned && (!ok || when.After(previous)) {
				provisioned[key] = when
			}
			if entry.kind != "" && entry.kind != "order_create_error_still_provisioning" {
				if previous, ok := latestErrors[key]; !ok || when.After(previous) {
					latestErrors[key] = when
				}
			}
		}
		if entry.order == "" || entry.reseller == "" {
			continue
		}
		if previous := resellers[key]; previous != "" && previous != entry.reseller {
			conflicts[key] = true
		}
		resellers[key] = entry.reseller
	}
	for order := range orders {
		if orderTypes[order] == "" || typeConflicts[order] {
			orderTypes[order] = "unknown"
		}
	}
	// Ключи всех видов позволяют снять старое уведомление после перезапуска.
	for order, confirmed := range provisioned {
		for _, kind := range []string{"order_create_error_not_found", "order_provision_error_timeout", "order_create_error_still_provisioning", "order_create_error_renewal_block_period", "order_create_error_trial_lasts", "other_error"} {
			result.resolvedBefore[issueKey(order.project, kind, order.order)] = confirmed
		}
	}
	groups := make(map[string]*Issue)
	for index, record := range records {
		if filter.Include != nil && !filter.Include.MatchString(record.Line) || filter.Exclude != nil && filter.Exclude.MatchString(record.Line) {
			result.Filtered++
			continue
		}
		entry := parsed[index]
		if entry.kind == "" {
			continue
		}
		result.Errors++
		if entry.order == "" {
			result.ErrorsWithoutOrder++
		} else if order := (orderKey{record.Project, entry.order}); entry.kind != "order_create_error_still_provisioning" {
			if confirmed, ok := provisioned[order]; !ok || !record.Timestamp.Before(confirmed) {
				ordersWithErrors[order] = struct{}{}
			}
		}
		// Ключ зависит от сущности и вида ошибки, а не от динамического текста или секретов.
		key := issueKey(record.Project, entry.kind, entry.order)
		when := record.Timestamp.UTC()
		issue := groups[key]
		if issue == nil {
			order := orderKey{record.Project, entry.order}
			issue = &Issue{Key: key, Kind: entry.kind, OrderID: clean(entry.order, safeIdentifier), OrderType: orderTypes[order], First: when, Last: when}
			if issue.OrderType == "" {
				issue.OrderType = "unknown"
			}
			issue.ResellerConflict = conflicts[order]
			if !issue.ResellerConflict {
				issue.ResellerID = clean(resellers[order], safeIdentifier)
			}
			groups[key] = issue
		}
		issue.Count++
		issue.Critical = issue.Critical || entry.critical
		if when.Before(issue.First) {
			issue.First = when
		}
		if when.After(issue.Last) || when.Equal(issue.Last) && entry.pod+"\x00"+entry.server > issue.Pod+"\x00"+issue.Server {
			issue.Last, issue.Pod, issue.Server = when, entry.pod, entry.server
		}
	}
	for _, issue := range groups {
		result.Issues = append(result.Issues, *issue)
	}
	result.Orders = len(orders)
	result.OrdersWithErrors = len(ordersWithErrors)
	counts := make(map[string]OrderCounts)
	for order := range orders {
		kind := orderTypes[order]
		count := counts[kind]
		count.Type, count.Total = kind, count.Total+1
		if _, ok := ordersWithErrors[order]; ok {
			count.WithErrors++
		} else if confirmed, ok := provisioned[order]; ok {
			if lastError, exists := latestErrors[order]; !exists || lastError.Before(confirmed) {
				result.OrdersSucceeded++
				count.Succeeded++
			}
		}
		count.Other = count.Total - count.Succeeded - count.WithErrors
		counts[kind] = count
	}
	result.OrdersOther = result.Orders - result.OrdersSucceeded - result.OrdersWithErrors
	for _, kind := range []string{"new", "renew", "cancel", "unknown"} {
		if count, ok := counts[kind]; ok {
			result.ByType = append(result.ByType, count)
		}
	}
	sort.Slice(result.Issues, func(i, j int) bool {
		left, right := result.Issues[i], result.Issues[j]
		if left.Critical != right.Critical {
			return left.Critical
		}
		if left.Count != right.Count {
			return left.Count > right.Count
		}
		return left.Key < right.Key
	})
	return result
}

// EnrichResellers дополняет только принадлежность заказа, сохраняя ошибки и счётчики периода.
// Вызывается для снимка одного проекта и истории того же источника и проекта.
func EnrichResellers(snapshot *Snapshot, history map[string][]string) {
	for index := range snapshot.Issues {
		issue := &snapshot.Issues[index]
		if snapshot.IsResolved(*issue) || issue.OrderID == "" {
			continue
		}
		if issue.ResellerConflict {
			issue.ResellerID = ""
			continue
		}
		reseller := issue.ResellerID
		for _, candidate := range history[issue.OrderID] {
			if !safeIdentifier.MatchString(candidate) {
				continue
			}
			if reseller != "" && reseller != candidate {
				issue.ResellerID, issue.ResellerConflict = "", true
				break
			}
			reseller = candidate
		}
		if !issue.ResellerConflict {
			issue.ResellerID = reseller
		}
	}
}

func parseRecord(record model.LogRecord) parsedRecord {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(record.Line), &fields) != nil {
		fields = nil
	}
	entry := parsedRecord{
		message: jsonString(fields, "msg", "message"), level: jsonString(fields, "level", "severity"),
		order: jsonString(fields, "orderId", "order_id"), reseller: jsonString(fields, "resellerId", "reseller_id"),
		orderType: jsonString(fields, "type", "orderType", "order_type"),
	}
	if entry.orderType != "" && entry.orderType != "new" && entry.orderType != "renew" && entry.orderType != "cancel" {
		entry.orderType = "unknown"
	}
	if fields == nil {
		entry.message = record.Line
	}
	// Числовые уровни 50/60 сами по себе не подтверждают ошибку; id позиции не становится заказом.
	if jsonString(fields, "context") == "orders" {
		switch entry.message {
		case "creating order", "sending order to provision", "order created", "getting order", "order received successfully", "checking order exists":
			if entry.order == "" {
				entry.order = jsonString(fields, "id")
			}
		case "order create error order not found":
			entry.kind = "order_create_error_not_found"
		case "error provisioned, timeout exceeded when trying to connect":
			entry.kind = "order_provision_error_timeout"
		case "order create error order still being provision":
			entry.kind = "order_create_error_still_provisioning"
		case "order create error order item during the renewal block period":
			entry.kind = "order_create_error_renewal_block_period"
		case "order create error order item trial lasts":
			entry.kind = "order_create_error_trial_lasts"
		case "order provisioned":
			entry.provisioned = jsonString(fields, "orderId") != ""
		}
	}
	entry.pod = contextValue(record, fields, "pod", "pod_name")
	entry.server = contextValue(record, fields, "server", "node_name", "node", "host", "hostname", "instance")
	return entry
}

func issueKey(project, kind, order string) string {
	identity, _ := json.Marshal([3]string{project, kind, order})
	digest := sha256.Sum256(identity)
	return hex.EncodeToString(digest[:])
}

func errorLevel(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "fatal", "critical":
		return true
	}
	return false
}

func jsonString(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		var value string
		if json.Unmarshal(fields[name], &value) == nil && value != "" {
			return value
		}
	}
	return ""
}

// Разрешаем только выбранные поля: произвольные labels, metadata и JSON наружу не копируются.
func contextValue(record model.LogRecord, fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		for _, value := range []string{record.Labels[name], record.Metadata[name], jsonString(fields, name)} {
			if value = clean(value, safeInfrastructure); value != "" {
				return value
			}
		}
	}
	return ""
}

func clean(value string, allowed *regexp.Regexp) string {
	if allowed.MatchString(value) {
		return value
	}
	return ""
}
