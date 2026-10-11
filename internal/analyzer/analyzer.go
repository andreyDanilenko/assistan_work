package analyzer

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"loki-analyzer/internal/model"
)

// Analyzer распознает события и строит историю заказов без обращения к источникам.
type Analyzer struct{}

// New создает анализатор с правилами для наблюдаемых сообщений sds-orders.
func New() *Analyzer { return &Analyzer{} }

// Analyze обрабатывает одну выборку без объединения с прошлыми запусками.
// Повторные записи остаются отдельными событиями; полнота истории здесь неизвестна.
func (a *Analyzer) Analyze(ctx context.Context, records []model.LogRecord) (model.AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return model.AnalysisResult{}, err
	}
	result := model.AnalysisResult{
		TotalRecords: len(records),
		Orders:       []model.OrderState{},
		Skipped:      make(map[string]int),
		Resellers:    []model.ResellerSummary{},
	}
	// Одинаковые ID из разных проектов относятся к разным заказам.
	type orderKey struct{ project, id string }
	histories := make(map[orderKey][]model.OrderEvent)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return model.AnalysisResult{}, err
		}
		event, reason := parseEvent(record)
		if reason != "" {
			// Нераспознанные строки учитываем по причине, но не включаем в историю.
			result.Skipped[reason]++
			continue
		}
		key := orderKey{event.Project, event.OrderID}
		histories[key] = append(histories[key], event)
	}
	// Сначала считаем каждый заказ, затем строим общую сводку по реселлерам.
	for _, events := range histories {
		if err := ctx.Err(); err != nil {
			return model.AnalysisResult{}, err
		}
		order := summarizeOrder(events)
		result.Orders = append(result.Orders, order)
		result.ErrorEvents += order.ErrorCount
	}
	slices.SortFunc(result.Orders, func(left, right model.OrderState) int {
		return cmp.Or(cmp.Compare(left.Project, right.Project), cmp.Compare(left.OrderID, right.OrderID))
	})
	result.Resellers = summarizeResellers(result.Orders)
	if err := ctx.Err(); err != nil {
		return model.AnalysisResult{}, err
	}
	return result, nil
}

// parseEvent отделяет разбор JSON от распознавания известных событий контекста orders.
// В результат попадают только поля OrderEvent; исходная строка и метки сюда не копируются.
func parseEvent(record model.LogRecord) (model.OrderEvent, string) {
	log, err := model.ParseOrderLog(record.Line)
	if err != nil {
		return model.OrderEvent{}, "invalid_json"
	}
	if log.Context != "orders" {
		return model.OrderEvent{}, "unrelated_context"
	}
	event := model.OrderEvent{
		Project: record.Project, Timestamp: record.Timestamp.UTC(),
		OrderID: log.OrderID, ResellerID: log.ResellerID,
		SourceStatus: log.Status, Level: log.Level, ApplicationTimeMS: log.TimeMS,
	}
	// Поле id может обозначать позицию: используем его как ID заказа только для известных сообщений.
	orderIDFromID := false
	switch log.Message {
	case "creating order":
		event.Type, orderIDFromID = "creating_order", true
	case "sending order to provision":
		event.Type, orderIDFromID = "sending_order_to_provision", true
	case "order created":
		event.Type, orderIDFromID = "order_created", true
	case "getting order":
		event.Type, orderIDFromID = "getting_order", true
	case "order received successfully":
		event.Type, orderIDFromID = "order_received_successfully", true
	case "checking order exists":
		event.Type, orderIDFromID = "checking_order_exists", true
	case "create order item":
		event.Type, event.ItemID = "create_order_item", log.ID
	case "remove order field in item":
		event.Type, event.ItemID = "remove_order_field_in_item", log.ID
	case "order items provisioned":
		event.Type = "order_items_provisioned"
	case "order provisioned":
		event.Type = "order_provisioned"
	case "error provisioned, timeout exceeded when trying to connect":
		event.Type, event.IsError = "order_provision_error_timeout", true
	case "get artifacts skipped, order not completed or expired":
		event.Type = "order_artifacts_skipped"
	case "order create error order still being provision":
		event.Type, event.IsError = "order_create_error_still_provisioning", true
	case "order create error order item during the renewal block period":
		event.Type, event.IsError = "order_create_error_renewal_block_period", true
	case "order create error order item trial lasts":
		event.Type, event.IsError = "order_create_error_trial_lasts", true
	case "order create error order not found":
		event.Type, event.IsError = "order_create_error_not_found", true
	default:
		return model.OrderEvent{}, "unknown_event"
	}
	// Явный orderId всегда имеет приоритет; при неоднозначности запись пропускаем.
	if event.OrderID == "" && orderIDFromID {
		event.OrderID = log.ID
	}
	if strings.TrimSpace(event.OrderID) == "" {
		return model.OrderEvent{}, "missing_order_id"
	}
	return event, ""
}

// showsActivity отличает обработку заказа от чтения и ошибок отдельных операций.
func showsActivity(event model.OrderEvent) bool {
	// Успешное чтение само по себе не подтверждает продвижение обработки.
	if event.IsError {
		return false
	}
	switch event.Type {
	case "getting_order", "checking_order_exists", "order_received_successfully", "order_artifacts_skipped":
		return false
	default:
		return true
	}
}

// summarizeOrder собирает наблюдаемые состояние, ошибки и принадлежность заказа.
func summarizeOrder(events []model.OrderEvent) model.OrderState {
	slices.SortFunc(events, compareEvents)
	first, last := events[0], events[len(events)-1]
	order := model.OrderState{
		Project: first.Project, OrderID: first.OrderID, State: model.OrderUnknown,
		FirstSeen: first.Timestamp, LastSeen: last.Timestamp, Events: events,
	}
	for _, event := range events {
		// Подтверждение этапа сохраняется при последующих чтениях, активности и ошибках.
		switch {
		case event.Type == "order_provisioned":
			order.State = model.OrderProvisioned
		case order.State == model.OrderUnknown && showsActivity(event):
			order.State = model.OrderInProgress
		}
		if event.SourceStatus != "" {
			order.SourceStatus = event.SourceStatus
		}
		if event.IsError {
			order.ErrorCount++
		}
		// Если встретились разные реселлеры, отмечаем конфликт вместо выбора одного из них.
		if event.ResellerID == "" || order.ResellerConflict {
			continue
		}
		if order.ResellerID != "" && order.ResellerID != event.ResellerID {
			order.ResellerID = ""
			order.ResellerConflict = true
		} else {
			order.ResellerID = event.ResellerID
		}
	}
	// Provisioned подтверждает этап обработки, но не окончательный результат всего заказа.
	return order
}

// compareEvents при одинаковом времени задает стабильный технический порядок.
// Этот порядок не доказывает реальную последовательность бизнес-событий.
func compareEvents(left, right model.OrderEvent) int {
	return cmp.Or(
		left.Timestamp.Compare(right.Timestamp),
		cmp.Compare(left.Type, right.Type),
		cmp.Compare(left.ItemID, right.ItemID),
		cmp.Compare(left.ResellerID, right.ResellerID),
		cmp.Compare(left.SourceStatus, right.SourceStatus),
		compareOptional(left.Level, right.Level),
		compareOptional(left.ApplicationTimeMS, right.ApplicationTimeMS),
	)
}

// compareOptional отличает отсутствующее число от нуля при сортировке событий.
func compareOptional[T ~int | ~int64](left, right *T) int {
	switch {
	case left == nil && right == nil:
		return 0
	case left == nil:
		return -1
	case right == nil:
		return 1
	default:
		return cmp.Compare(*left, *right)
	}
}

// summarizeResellers считает заказы и сообщения об ошибках отдельно, в пределах проекта.
// Заказы без однозначного реселлера попадают в группу с пустым ID.
func summarizeResellers(orders []model.OrderState) []model.ResellerSummary {
	type resellerKey struct{ project, id string }
	groups := make(map[resellerKey]model.ResellerSummary)
	for _, order := range orders {
		key := resellerKey{order.Project, order.ResellerID}
		group := groups[key]
		group.Project, group.ResellerID = key.project, key.id
		group.Orders++
		group.ErrorEvents += order.ErrorCount
		switch order.State {
		case model.OrderInProgress:
			group.InProgress++
		case model.OrderProvisioned:
			group.Provisioned++
		case model.OrderSucceeded:
			group.Succeeded++
		case model.OrderFailed:
			group.Failed++
		default:
			group.Unknown++
		}
		groups[key] = group
	}
	result := make([]model.ResellerSummary, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}
	slices.SortFunc(result, func(left, right model.ResellerSummary) int {
		return cmp.Or(cmp.Compare(left.Project, right.Project), cmp.Compare(left.ResellerID, right.ResellerID))
	})
	return result
}
