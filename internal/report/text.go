package report

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
)

// Ограничения сокращают только подробный вывод; исходные события и общие итоги не меняются.
const (
	displayedEvents = 5
	displayedOrders = 10
)

// WriteFile сохраняет привычный подробный отчёт команды analyze.
func WriteFile(output io.Writer, result model.AnalysisResult, allOrders bool) error {
	var text textBuffer
	text.WriteString("Отчет по заказам\n")
	// Демонстрационные данные помечает источник; по ID заказа или имени файла это не угадываем.
	if result.SyntheticRecords > 0 && result.SyntheticRecords == result.TotalRecords {
		text.WriteString("Демонстрационный пример: заказы и реселлеры вымышлены.\n")
	} else if result.SyntheticRecords > 0 {
		fmt.Fprintf(&text, "Смешанные данные: %d из %d записей помечены как демонстрационные.\n", result.SyntheticRecords, result.TotalRecords)
	}
	skipped := 0
	for _, count := range result.Skipped {
		skipped += count
	}
	fmt.Fprintf(&text, "Прочитано записей: %d. Связано с заказами: %d.\n", result.TotalRecords, result.TotalRecords-skipped)
	fmt.Fprintf(&text, "Найдено заказов: %d. Распознано ошибок операций: %d.\n", len(result.Orders), result.ErrorEvents)
	// Считаем заказы отдельно от событий ошибок: у одного заказа может быть несколько ошибок.
	confirmed, withErrors := 0, 0
	for _, order := range result.Orders {
		if order.State == model.OrderProvisioned {
			confirmed++
		}
		if order.ErrorCount > 0 {
			withErrors++
		}
	}
	fmt.Fprintf(&text, "Этап обработки подтвержден у %d заказов. Ошибки операций есть в истории %d заказов.\n", confirmed, withErrors)
	text.WriteString("В отчете учтены только события файла. История заказа может быть неполной.\n")
	writeDetails(&text, result, allOrders, true, nil)

	_, err := io.WriteString(output, text.String())
	return err
}

// WriteDatabase показывает посчитанные актуальные ошибки, а не выгрузку записей из базы.
func WriteDatabase(output io.Writer, snapshot monitor.Snapshot, project string, start, end time.Time, names map[string]string) error {
	text := textBuffer{limit: 8 << 20}
	text.WriteString("Отчет по ошибкам заказов\n")
	fmt.Fprintf(&text, "Проект: %q\nПериод: %s — %s\n", project, start.UTC().Format("02.01.2006 15:04:05 UTC"), end.UTC().Format("02.01.2006 15:04:05 UTC"))
	fmt.Fprintf(&text, "Уникальных заказов: %d. Успешно: %d. С актуальной ошибкой: %d. Результат неизвестен: %d.\n", snapshot.Orders, snapshot.OrdersSucceeded, snapshot.OrdersWithErrors, snapshot.OrdersOther)
	text.WriteString("Успех означает, что сервис подтвердил обработку заказа; более поздняя ошибка учитывается отдельно.\n")
	for _, kind := range []string{"new", "renew", "cancel", "unknown"} {
		for _, counts := range snapshot.ByType {
			if orderType(counts.Type) == kind {
				fmt.Fprintf(&text, "  %s: всего %d · успешно %d · с ошибкой %d · результат неизвестен %d.\n", typeDescription(kind), counts.Total, counts.Succeeded, counts.WithErrors, counts.Other)
			}
		}
	}
	text.WriteString("Источник: только сохранённые логи SQLite.\n")
	if !snapshot.Coverage.Known {
		text.WriteString("Полнота сбора за период не подтверждена.\n")
	} else if len(snapshot.Coverage.Gaps) == 0 {
		text.WriteString("Все участки периода получены из Loki. Поздние логи могут дополнить результат.\n")
	} else {
		text.WriteString("НЕПОЛНЫЙ СБОР: счётчики только по сохранённым данным.\n")
		for _, gap := range snapshot.Coverage.Gaps {
			fmt.Fprintf(&text, "  Не подтверждено: %s — %s UTC\n", gap.Start.UTC().Format("02.01.2006 15:04:05"), gap.End.UTC().Format("02.01.2006 15:04:05"))
		}
	}
	if snapshot.Filtered > 0 {
		fmt.Fprintf(&text, "Исключено фильтром записей: %d.\n", snapshot.Filtered)
	}

	groups := groupErrors(snapshot)
	if len(groups) == 0 {
		text.WriteString("\nАктуальных ошибок в сохранённых данных за период нет.\n")
	} else {
		text.WriteString("\nКатегории ошибок за период:\n")
		for _, group := range groups {
			fmt.Fprintf(&text, "  %s Заказов: %d.\n", errorDescription(group.kind), len(group.orders))
		}
	}
	if len(groups) > 0 {
		writeResellerSummary(&text, groups, names)
		text.WriteString("\nПодробности: категории → реселлеры → заказы\n")
	}
	for _, group := range groups {
		fmt.Fprintf(&text, "\n%s\nЗатронуто уникальных заказов: %d.\n", errorDescription(group.kind), len(group.orders))
		writeErrorResellers(&text, group, names)
	}
	if len(groups) > 0 {
		text.WriteString("\nВ шапке каждый заказ учтён один раз. Заказ с несколькими видами ошибок указан в каждом соответствующем разделе.\n")
	}
	if text.err != nil {
		return text.err
	}
	_, err := io.WriteString(output, text.String())
	return err
}

func errorDescription(kind string) string {
	if description := eventDescription(kind); description != "Событие без описания." {
		return description
	}
	return "Нераспознанный вид ошибки."
}

// Для каждого вида ошибки сохраняем один результат по ID заказа. Повторы логов не увеличивают число заказов.
type errorGroup struct {
	kind         string
	orders       map[string]monitor.Issue
	withoutOrder []monitor.Issue
}

func groupErrors(snapshot monitor.Snapshot) []errorGroup {
	byKind := make(map[string]*errorGroup)
	for _, issue := range snapshot.Issues {
		if snapshot.IsResolved(issue) {
			continue
		}
		group := byKind[issue.Kind]
		if group == nil {
			group = &errorGroup{kind: issue.Kind, orders: make(map[string]monitor.Issue)}
			byKind[issue.Kind] = group
		}
		if issue.OrderID == "" {
			group.withoutOrder = append(group.withoutOrder, issue)
			continue
		}
		previous, exists := group.orders[issue.OrderID]
		// При равном времени выбираем одинаково независимо от порядка входных записей.
		details := issue.ResellerID + "\x00" + issue.OrderType + "\x00" + issue.Pod + "\x00" + issue.Server
		previousDetails := previous.ResellerID + "\x00" + previous.OrderType + "\x00" + previous.Pod + "\x00" + previous.Server
		if !exists || issue.Last.After(previous.Last) || issue.Last.Equal(previous.Last) && details > previousDetails {
			group.orders[issue.OrderID] = issue
		}
	}
	groups := make([]errorGroup, 0, len(byKind))
	for _, group := range byKind {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].orders) != len(groups[j].orders) {
			return len(groups[i].orders) > len(groups[j].orders)
		}
		return groups[i].kind < groups[j].kind
	})
	return groups
}

// Сводка и подробности используют одну группировку: имя не заменяет ID реселлера.
type resellerErrors struct {
	id           string
	conflict     bool
	orders       []monitor.Issue
	withoutOrder int
}

func groupResellers(groups []errorGroup) []*resellerErrors {
	// Один заказ может иметь разные ошибки, но в сводке реселлера считается один раз.
	orders := make(map[string]monitor.Issue)
	var withoutOrder []monitor.Issue
	for _, group := range groups {
		withoutOrder = append(withoutOrder, group.withoutOrder...)
		for id, issue := range group.orders {
			previous, exists := orders[id]
			if exists {
				issue.ResellerConflict = issue.ResellerConflict || previous.ResellerConflict ||
					issue.ResellerID != "" && previous.ResellerID != "" && issue.ResellerID != previous.ResellerID
				if issue.ResellerID == "" {
					issue.ResellerID = previous.ResellerID
				}
			}
			if issue.ResellerConflict {
				issue.ResellerID = ""
			}
			orders[id] = issue
		}
	}

	byReseller := make(map[string]*resellerErrors)
	add := func(issue monitor.Issue) {
		key := issue.ResellerID
		if issue.ResellerConflict {
			key = "\x00conflict"
		}
		reseller := byReseller[key]
		if reseller == nil {
			reseller = &resellerErrors{id: issue.ResellerID, conflict: issue.ResellerConflict}
			byReseller[key] = reseller
		}
		if issue.OrderID == "" {
			reseller.withoutOrder += issue.Count
		} else {
			reseller.orders = append(reseller.orders, issue)
		}
	}
	for _, issue := range orders {
		add(issue)
	}
	for _, issue := range withoutOrder {
		add(issue)
	}
	resellers := make([]*resellerErrors, 0, len(byReseller))
	for _, reseller := range byReseller {
		sort.Slice(reseller.orders, func(i, j int) bool { return reseller.orders[i].OrderID < reseller.orders[j].OrderID })
		resellers = append(resellers, reseller)
	}
	sort.Slice(resellers, func(i, j int) bool {
		if len(resellers[i].orders) != len(resellers[j].orders) {
			return len(resellers[i].orders) > len(resellers[j].orders)
		}
		if resellers[i].conflict != resellers[j].conflict {
			return !resellers[i].conflict
		}
		return resellers[i].id < resellers[j].id
	})
	return resellers
}

func (reseller resellerErrors) name(names map[string]string) string {
	if reseller.conflict {
		return "в сохранённых логах указаны разные ID; принадлежность требует проверки"
	}
	return resellerName(reseller.id, names)
}

func writeResellerSummary(text *textBuffer, groups []errorGroup, names map[string]string) {
	text.WriteString("\nРеселлеры с актуальными ошибками:\n")
	for _, reseller := range groupResellers(groups) {
		counts := make(map[string]int)
		for _, issue := range reseller.orders {
			counts[orderType(issue.OrderType)]++
		}
		fmt.Fprintf(text, "  Реселлер: %s. Уникальных заказов с ошибками: %d.\n", reseller.name(names), len(reseller.orders))
		fmt.Fprintf(text, "    new: %d · renew: %d · cancel: %d · тип не определён: %d.\n", counts["new"], counts["renew"], counts["cancel"], counts["unknown"])
		if reseller.withoutOrder > 0 {
			fmt.Fprintf(text, "    Без ID заказа: %d записей; в число заказов не входят.\n", reseller.withoutOrder)
		}
	}
	text.WriteString("У одного заказа может быть несколько ошибок: в итогах реселлера он учтён один раз.\n")
}

func writeErrorResellers(text *textBuffer, group errorGroup, names map[string]string) {
	for _, reseller := range groupResellers([]errorGroup{group}) {
		fmt.Fprintf(text, "  Реселлер: %s. Заказов с этой ошибкой: %d.\n", reseller.name(names), len(reseller.orders))
		for _, kind := range []string{"new", "renew", "cancel", "unknown"} {
			count := 0
			for _, issue := range reseller.orders {
				if orderType(issue.OrderType) == kind {
					count++
				}
			}
			if count == 0 {
				continue
			}
			fmt.Fprintf(text, "    %s · заказов: %d\n", typeDescription(kind), count)
			for _, issue := range reseller.orders {
				if orderType(issue.OrderType) != kind {
					continue
				}
				fmt.Fprintf(text, "      • ID заказа: %q", issue.OrderID)
				if !issue.Last.IsZero() {
					fmt.Fprintf(text, " · последняя ошибка: %s", issue.Last.UTC().Format("02.01.2006 15:04:05 UTC"))
				}
				if issue.Pod != "" {
					fmt.Fprintf(text, " · pod: %q", issue.Pod)
				}
				if issue.Server != "" {
					fmt.Fprintf(text, " · сервер: %q", issue.Server)
				}
				text.WriteString("\n")
			}
		}
		if reseller.withoutOrder > 0 {
			fmt.Fprintf(text, "    Без ID заказа: %d записей; в число заказов не входят.\n", reseller.withoutOrder)
		}
	}
}

func orderType(kind string) string {
	switch kind {
	case "new", "renew", "cancel":
		return kind
	default:
		return "unknown"
	}
}

func typeDescription(kind string) string {
	if kind == "unknown" {
		return "тип не определён"
	}
	return kind
}

// Подробности CLI-анализа файла: история событий и сводка по реселлерам.
func writeDetails(text *textBuffer, result model.AnalysisResult, allOrders, fromFile bool, names map[string]string) {
	skipped := 0
	for _, count := range result.Skipped {
		skipped += count
	}
	// Все итоги уже рассчитаны по полному набору. Для подробностей сортируем отдельную копию.
	orders := append([]model.OrderState(nil), result.Orders...)
	sort.SliceStable(orders, func(i, j int) bool { return orderPriority(orders[i]) < orderPriority(orders[j]) })
	if !allOrders && len(orders) > displayedOrders {
		fmt.Fprintf(text, "Подробно показано %d из %d заказов: сначала с ошибками и без подтверждения.", displayedOrders, len(orders))
		if fromFile {
			text.WriteString(" Все заказы: --all-orders.")
		}
		text.WriteString("\n")
		orders = orders[:displayedOrders]
	}
	for _, order := range orders {
		printOrder(text, order, names)
	}
	printResellers(text, result.Resellers, names)
	if skipped > 0 {
		fmt.Fprintf(text, "\nЗаписей, не включенных в историю заказов: %d.\n", skipped)
		reasons := make([]string, 0, len(result.Skipped))
		for reason := range result.Skipped {
			reasons = append(reasons, reason)
		}
		// Порядок обхода map случаен; причины показываем в устойчивом порядке.
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Fprintf(text, "  %s: %d.\n", skipDescription(reason), result.Skipped[reason])
		}
	}
}

// Не отправляем частичный файл, если отчёт превышает допустимый размер.
type textBuffer struct {
	strings.Builder
	limit int
	err   error
}

func (b *textBuffer) Write(p []byte) (int, error) {
	if b.err == nil && b.limit > 0 && len(p) > b.limit-b.Len() {
		b.err = errors.New("отчёт превышает 8 МиБ; сократите период")
	}
	if b.err != nil {
		return 0, b.err
	}
	return b.Builder.Write(p)
}

func (b *textBuffer) WriteString(value string) (int, error) {
	if b.err == nil && b.limit > 0 && len(value) > b.limit-b.Len() {
		b.err = errors.New("отчёт превышает 8 МиБ; сократите период")
	}
	if b.err != nil {
		return 0, b.err
	}
	return b.Builder.WriteString(value)
}

// orderPriority ставит сначала ошибки, затем заказы без подтверждения, затем остальные.
func orderPriority(order model.OrderState) int {
	if order.ErrorCount > 0 {
		return 0
	}
	if order.State != model.OrderProvisioned && order.State != model.OrderSucceeded {
		return 1
	}
	return 2
}

func printOrder(text *textBuffer, order model.OrderState, names map[string]string) {
	// Анализатор уже упорядочил историю; показываем последние события и сохраняем полные счетчики.
	start := max(0, len(order.Events)-displayedEvents)
	// %q и resellerName экранируют ID и проект из внешних данных перед выводом в терминал.
	fmt.Fprintf(text, "\nЗаказ %q\n  Проект: %q. Реселлер: %s.\n", order.OrderID, order.Project, resellerName(order.ResellerID, names))
	fmt.Fprintf(text, "  %s\n", orderDescription(order))
	if order.ResellerConflict {
		text.WriteString("  В событиях указаны разные реселлеры; принадлежность заказа не определена.\n")
	}
	if order.ErrorCount > 0 {
		fmt.Fprintf(text, "  Ошибок операций в истории: %d.\n", order.ErrorCount)
		// Последняя ошибка остается видимой, даже если уже не попадает в короткую историю.
		for i := len(order.Events) - 1; i >= 0; i-- {
			if order.Events[i].IsError {
				if i < start {
					fmt.Fprintf(text, "  Более раннее событие: %s\n", eventDescription(order.Events[i].Type))
				}
				break
			}
		}
	}
	if len(order.Events) == 0 {
		text.WriteString("  События для показа отсутствуют.\n")
		return
	}
	if start > 0 {
		fmt.Fprintf(text, "  Последние события (показано %d из %d):\n", displayedEvents, len(order.Events))
	} else {
		text.WriteString("  Что происходило:\n")
	}
	for _, event := range order.Events[start:] {
		fmt.Fprintf(text, "    %s — %s\n", event.Timestamp.UTC().Format("02.01.2006 15:04:05 UTC"), eventDescription(event.Type))
	}
}

// printResellers использует сводку всех записей, а не только показанных выше заказов.
func printResellers(text *textBuffer, resellers []model.ResellerSummary, names map[string]string) {
	if len(resellers) == 0 {
		return
	}
	text.WriteString("\nСводка по реселлерам:\n")
	for _, reseller := range resellers {
		fmt.Fprintf(text, "  %s (проект %q): заказов — %d, с подтвержденным этапом обработки — %d, известных ошибок операций — %d.\n",
			resellerName(reseller.ResellerID, names), reseller.Project, reseller.Orders, reseller.Provisioned, reseller.ErrorEvents)
	}
}

func resellerName(id string, names map[string]string) string {
	if id == "" {
		return "не определен"
	}
	// Название дополняет ID для чтения; группировка по-прежнему строится по ID.
	if name := names[id]; name != "" {
		return fmt.Sprintf("%q (ID: %q)", name, id)
	}
	return strconv.Quote(id)
}

// orderDescription объясняет установленное анализатором состояние без вывода о конечном успехе по чтению.
func orderDescription(order model.OrderState) string {
	switch order.State {
	case model.OrderProvisioned:
		return "Сервис подтвердил выполнение этапа обработки заказа."
	case model.OrderSucceeded:
		return "Заказ успешно завершен."
	case model.OrderFailed:
		return "Заказ завершился с ошибкой."
	case model.OrderInProgress:
		return "Есть шаги создания или обработки заказа. Конечный результат пока не установлен."
	}
	if len(order.Events) > 0 {
		for _, event := range order.Events {
			if event.Type != "getting_order" && event.Type != "checking_order_exists" && event.Type != "order_received_successfully" && event.Type != "order_artifacts_skipped" {
				return "Данных недостаточно, чтобы определить результат заказа."
			}
		}
		return "Видно только чтение данных заказа. Ход обработки неизвестен."
	}
	return "Данных недостаточно, чтобы определить результат заказа."
}

// eventDescription переводит внутренние типы событий в понятные сообщения; сырой лог сюда не выводится.
func eventDescription(kind string) string {
	switch kind {
	case "creating_order":
		return "Начато создание заказа."
	case "create_order_item":
		return "Создается позиция заказа."
	case "sending_order_to_provision":
		return "Заказ передается на обработку."
	case "order_created":
		return "Сервис сообщил о создании заказа."
	case "getting_order":
		return "Запрошены данные заказа."
	case "checking_order_exists":
		return "Проверяется наличие заказа."
	case "order_received_successfully":
		return "Данные заказа получены в ответ на запрос."
	case "remove_order_field_in_item":
		return "В данных позиции удаляется поле заказа."
	case "order_items_provisioned":
		return "Сервис подтвердил обработку позиций заказа."
	case "order_provisioned":
		return "Сервис подтвердил этап обработки заказа."
	case "order_create_error_still_provisioning":
		return "Ошибка создания: приложение сообщает, что заказ еще обрабатывается."
	case "order_create_error_not_found":
		return "Ошибка создания: приложение сообщает, что заказ не найден."
	case "order_create_error_renewal_block_period":
		return "Ошибка создания: продление заблокировано на этот период."
	case "order_create_error_trial_lasts":
		return "Ошибка создания: пробный период ещё действует."
	case "order_provision_error_timeout":
		return "Ошибка обработки: истекло время ожидания подключения."
	case "order_artifacts_skipped":
		return "Выдача артефактов пропущена: заказ еще не завершен или срок его действия истек."
	default:
		return "Событие без описания."
	}
}

// skipDescription объясняет, почему запись не попала в историю, не раскрывая ее содержимое.
func skipDescription(reason string) string {
	switch reason {
	case "invalid_json":
		return "Строка не соответствует ожидаемому формату сообщения"
	case "unrelated_context":
		return "Сообщение не относится к контексту заказов"
	case "missing_order_id":
		return "В сообщении не найден номер заказа"
	case "unknown_event":
		return "Тип сообщения пока не поддерживается анализатором"
	default:
		return "Другая причина"
	}
}
