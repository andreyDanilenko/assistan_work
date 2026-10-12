package monitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/telegram"
)

// Run выполняет один цикл сразу, затем ждет интервал после завершения цикла.
// Так медленный запрос не порождает параллельные сборы и неограниченную очередь.
func (m *Monitor) Run(ctx context.Context, once bool) error {
	return m.run(ctx, once, nil)
}

// RunWithCommands запускает приём команд только после захвата единственной блокировки watch.
// Завершение сбора отменяет команды и ждёт их остановки перед освобождением базы и блокировки.
func (m *Monitor) RunWithCommands(ctx context.Context, commands func(context.Context)) error {
	return m.run(ctx, false, commands)
}

func (m *Monitor) run(ctx context.Context, once bool, commands func(context.Context)) error {
	release, err := m.openState()
	if err != nil {
		return err
	}
	defer release()
	if commands != nil {
		commandCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			commands(commandCtx)
		}()
		defer func() { cancel(); <-done }()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.cycle(ctx, time.Now().UTC()); err != nil {
			return err
		}
		if once {
			if m.state.SourceFailed {
				return errors.New("разовый сбор не подтвержден; проверьте доступ и лимиты Loki")
			}
			if m.reportFailed {
				return errors.New("сводка не построена; проверьте SQLite и уменьшите период отчёта")
			}
			if !m.config.DryRun && len(m.state.Pending) > 0 {
				return errors.New("часть сообщений ожидает доставки; состояние сохранено")
			}
			return nil
		}
		// Сбор остаётся частым; перед сроком сводки ждём только оставшееся время.
		// Если построение не удалось, обычный интервал защищает от частых повторов.
		delay := m.config.Interval
		if m.config.ReportOnly && !m.state.LastReport.IsZero() {
			untilReport := time.Until(m.state.LastReport.Add(m.config.ReportInterval))
			if untilReport > 0 && untilReport < delay {
				delay = untilReport
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Monitor) cycle(ctx context.Context, now time.Time) error {
	m.reportFailed = false
	// Очистка выполняется даже при последующем отказе Loki или пустой выборке.
	if !m.config.DryRun {
		cleanupCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
		_, err := m.archive.Prune(cleanupCtx, now)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("не удалось очистить SQLite; монитор остановлен, проверьте файл базы и свободное место")
		}
	}
	end := now.Add(-10 * time.Second)
	if !m.config.DryRun && !m.config.SessionStart.Before(end) {
		// Первые события запрашиваем после задержки Loki. Историю до запуска
		// не читаем даже ради первой сводки или проверки отсутствия логов.
		fmt.Fprintf(m.output, "Сбор с %s: ожидаем события текущей сессии. Следующий цикл через %s.\n", m.config.SessionStart.UTC().Format(time.RFC3339), m.config.Interval)
		return nil
	}
	collected, err := m.collect(ctx, end, now)
	if err != nil {
		return err
	}
	if !collected.complete {
		m.state.AlertIssues = nil
		m.removePending("alert")
		m.removePending("activity")
		fmt.Fprintln(m.diagnostic, "Сбор не подтвержден: ошибка Loki или неполный ответ. Отсутствие логов не оценивается. Сохранённые части остаются в базе; следующий цикл проверит свежее окно. Старые пропуски не догружаются.")
		if !m.state.SourceFailed {
			m.queue("source", "🟠 Нет подтвержденных данных Loki\nПроект: "+safe(m.config.Project)+"\nЧасть периода не получена полностью. Сохранённые части доступны; пропуск указан в отчёте. Следующий цикл проверит свежие логи. Это не означает отсутствие заказов или логов.", now)
		}
		m.state.SourceFailed = true
	} else {
		if m.state.SourceFailed && collected.portions > 0 {
			m.queue("source", "🟢 Loki снова отвечает\nПроект: "+safe(m.config.Project)+"\nСвежие логи получены и сохранены. Полнота истории указана в сводке; старые пропуски не догружаются.", now)
		}
		m.state.SourceFailed = false
	}
	if collected.complete {
		m.state.LastComplete = end
		if err := m.checkActivity(ctx, end, now); err != nil {
			return err
		}
	}
	if m.config.ReportOnly {
		// Сводка доступна и после неполного сбора: покрытие честно показывает пропуски.
		m.queuePeriodicReport(ctx, Analyze(collected.preview, Filter{Critical: m.filter.Critical}), end, now)
	} else if collected.complete {
		records := collected.preview
		if !m.config.DryRun {
			readCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
			records, err = m.config.ReadWindow(readCtx, m.windowStart(end), end)
			cancel()
			if err != nil {
				return errors.New("не удалось прочитать сохранённое окно; новые уведомления не построены")
			}
		}
		m.processAlertWindow(ctx, records, end, now)
	} else if m.reportDue(now) || m.hasPending("report") {
		m.queue("report", m.unavailableReport(now), now)
		m.state.LastReport = now
	}
	var reports, technical int
	for _, message := range m.state.Pending {
		if message.Kind == "report" || message.Kind == "alert" {
			reports++
		} else {
			technical++
		}
	}
	nextReportAt := m.state.LastReport.Add(m.config.ReportInterval)
	if m.reportFailed || m.state.LastReport.IsZero() {
		nextReportAt = now.Add(m.config.Interval)
	}
	nextReport := nextReportAt.UTC().Format(time.RFC3339)
	fmt.Fprintf(m.output, "%s | Сохранено частей: %d | Записей в ответах: %d | Текущий сбор полный: %t | Очередь: сводки %d, служебные %d | Следующая сводка: %s\n", now.Format(time.RFC3339), collected.portions, collected.records, collected.complete, reports, technical, nextReport)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := m.saveState(); err != nil {
		return err
	}
	return m.deliver(ctx, now)
}

// processAlertWindow обслуживает режим немедленных уведомлений WATCH_REPORT_ONLY=false.
func (m *Monitor) processAlertWindow(ctx context.Context, records []model.LogRecord, end, now time.Time) {
	start := m.windowStart(end)
	window := make([]model.LogRecord, 0, len(records))
	for _, record := range records {
		if !record.Timestamp.Before(start) && record.Timestamp.Before(end) {
			window = append(window, record)
		}
	}
	// Фильтры и паузы решают, когда уведомлять; сводка всегда описывает всё окно.
	snapshot := Analyze(window, Filter{Critical: m.filter.Critical})
	if !m.config.DryRun {
		coverageCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
		coverage, err := m.archive.Coverage(coverageCtx, m.logRange(start, end))
		cancel()
		if err == nil {
			snapshot.Coverage = coverage
		}
	}
	triggers := Analyze(window, m.filter)
	critical := make([]Issue, 0)
	for _, issue := range triggers.Issues {
		// Ожидание обработки не является падением. Поздний успех снимает раннюю ошибку.
		if snapshot.IsResolved(issue) {
			continue
		}
		if issue.Kind != "other_error" || issue.Critical || issue.Count >= m.config.ErrorThreshold {
			critical = append(critical, issue)
		}
	}
	m.bufferAlerts(critical, now)
	alertDue := len(m.state.AlertIssues) > 0
	if alertDue {
		m.queueReport("alert", m.summaryText(snapshot, start, end, true), start, end, now)
	} else {
		// Исчезнувшая или исправленная ошибка больше не запускает текущую сводку.
		m.removePending("alert")
	}
	refreshReport := m.reportDue(now)
	for _, message := range m.state.Pending {
		// Старый формат и сводка о недоступности заменяются после полного сбора.
		if message.Kind == "report" && message.ReportStart.IsZero() {
			refreshReport = true
		}
	}
	if refreshReport {
		// На первом цикле критическое сообщение уже подтверждает работу бота.
		if !m.state.LastReport.IsZero() || !alertDue || m.hasPending("report") {
			m.queueReport("report", m.summaryText(snapshot, start, end, false), start, end, now)
		}
		m.state.LastReport = now
	}
	fmt.Fprintf(m.output, "%s | Период: %s | Записей: %d | Заказов: %d | Заказов с ошибками: %d | Ошибок: %d | Очередь: %d\n", now.Format(time.RFC3339), durationText(end.Sub(start)), snapshot.Total, snapshot.Orders, snapshot.OrdersWithErrors, snapshot.Errors, len(m.state.Pending))
	if m.config.DryRun && !m.hasPending("report") {
		fmt.Fprintln(m.output, m.summaryText(snapshot, start, end, false))
	}
}

// queuePeriodicReport ставит сводку в очередь, когда наступил срок отчёта.
// Она учитывает сохранённые события всего периода; неполученные участки видны в покрытии.
func (m *Monitor) queuePeriodicReport(ctx context.Context, snapshot Snapshot, end, now time.Time) {
	m.removePending("alert")
	m.state.AlertIssues, m.state.Alerted = nil, nil
	if m.reportDue(now) {
		start := m.state.LastReportEnd
		if start.IsZero() {
			// Если первая попытка не удалась, её начало не сдвигается при повторе.
			if m.state.NextReportStart.IsZero() {
				m.state.NextReportStart = m.windowStart(end)
			}
			start = m.state.NextReportStart
		}
		if !start.Before(end) || m.config.DryRun {
			start = m.windowStart(end)
		}
		// Недоставленную сводку заменяем суммарной: её начало сохраняется.
		for _, message := range m.state.Pending {
			if message.Kind == "report" && !message.ReportStart.IsZero() && message.ReportStart.Before(start) {
				start = message.ReportStart
			}
		}
		// Сводка нового запуска начинается с его данных. Прежние записи
		// и пробелы по-прежнему доступны в отчёте по явному запросу /report.
		if !m.config.DryRun && start.Before(m.config.SessionStart) {
			start = m.config.SessionStart
		}
		trimmed := start.Before(now.Add(-48 * time.Hour))
		if trimmed {
			start = now.Add(-48 * time.Hour)
		}
		if !m.config.DryRun {
			reportCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
			var err error
			snapshot, err = m.config.BuildSnapshot(reportCtx, start, end)
			cancel()
			if err != nil {
				m.reportFailed = true
				fmt.Fprintln(m.diagnostic, "Сводка из SQLite не построена; счётчики не отправлены, период сохранён для следующей попытки. Проверьте базу и ограничение объёма отчёта.")
				return
			}
		}
		text := m.summaryText(snapshot, start, end, false)
		if trimmed {
			text += "\nПосле длительной паузы показаны только последние 48 часов хранения; ранние данные уже недоступны."
		}
		m.queueReport("report", text, start, end, now)
		// Курсор меняется только после успешного построения и постановки в очередь.
		m.state.LastReport, m.state.LastReportEnd = now, end
		m.state.NextReportStart = time.Time{}
	}
}

// bufferAlerts хранит только поводы для отправки текущего окна. Старые наблюдения
// не переносятся в новый период; готовый текст содержит все актуальные категории.
func (m *Monitor) bufferAlerts(issues []Issue, now time.Time) {
	for key, sent := range m.state.Alerted {
		if now.Sub(sent) >= m.config.Cooldown {
			delete(m.state.Alerted, key)
		}
	}
	m.state.AlertIssues = nil
	dropped := 0
	for _, issue := range issues {
		if sent, exists := m.state.Alerted[issue.Key]; exists && now.Sub(sent) < m.config.Cooldown {
			continue
		}
		if len(m.state.AlertIssues) == maxAlertGroups {
			dropped++
			continue
		}
		m.state.AlertIssues = append(m.state.AlertIssues, issue)
	}
	if dropped > 0 {
		m.state.AlertDropped += dropped
		fmt.Fprintln(m.diagnostic, "Буфер уведомлений заполнен; наблюдений групп сверх лимита:", dropped)
	}
}

func (m *Monitor) markAlertsDelivered(now time.Time) {
	if m.state.Alerted == nil {
		m.state.Alerted = make(map[string]time.Time)
	}
	for _, issue := range m.state.AlertIssues {
		m.state.Alerted[issue.Key] = now
	}
	m.state.AlertIssues = nil
	m.state.LastAlert = now
	// Ограничение антиспама не останавливает прием новых ошибок; старейшие ключи забываются явно.
	for len(m.state.Alerted) > maxCooldownGroups {
		oldest := ""
		for key, sent := range m.state.Alerted {
			if oldest == "" || sent.Before(m.state.Alerted[oldest]) || sent.Equal(m.state.Alerted[oldest]) && key < oldest {
				oldest = key
			}
		}
		delete(m.state.Alerted, oldest)
		m.state.CooldownEvicted++
	}
}

func (m *Monitor) reportDue(now time.Time) bool {
	return m.state.LastReport.IsZero() || now.Sub(m.state.LastReport) >= m.config.ReportInterval
}

func (m *Monitor) hasPending(kind string) bool {
	for _, message := range m.state.Pending {
		if message.Kind == kind {
			return true
		}
	}
	return false
}

// Для каждого назначения сохраняется один текст: отчет и состояние обновляются
// свежим значением. Срок повтора Telegram при обновлении текста сохраняется.
func (m *Monitor) queue(kind, text string, now time.Time) {
	for i := range m.state.Pending {
		if m.state.Pending[i].Kind == kind {
			m.state.Pending[i].Text = text
			m.state.Pending[i].ReportStart, m.state.Pending[i].ReportEnd = time.Time{}, time.Time{}
			return
		}
	}
	next := now
	if (kind == "source" || kind == "activity") && m.state.LastHealth.Add(m.config.Cooldown).After(next) {
		next = m.state.LastHealth.Add(m.config.Cooldown)
	}
	m.state.Pending = append(m.state.Pending, Message{Kind: kind, Text: text, NextTry: next})
}

// Период сохраняется вместе с текстом: кнопка не пересчитывает «последние 10 минут».
func (m *Monitor) queueReport(kind, text string, start, end, now time.Time) {
	m.queue(kind, text, now)
	for i := range m.state.Pending {
		if m.state.Pending[i].Kind == kind {
			m.state.Pending[i].ReportStart = start
			m.state.Pending[i].ReportEnd = end
			return
		}
	}
}

func (m *Monitor) removePending(kind string) {
	kept := m.state.Pending[:0]
	for _, message := range m.state.Pending {
		if message.Kind != kind {
			kept = append(kept, message)
		}
	}
	m.state.Pending = kept
}

func (m *Monitor) deliver(ctx context.Context, now time.Time) error {
	if !m.config.DryRun && now.Before(m.state.TelegramAfter) {
		return nil
	}
	for i := 0; i < len(m.state.Pending); {
		message := &m.state.Pending[i]
		if !m.config.DryRun && now.Before(message.NextTry) {
			i++
			continue
		}
		var err error
		if m.config.DryRun {
			fmt.Fprintf(m.output, "\n[Предпросмотр Telegram: %s]\n%s\n", message.Kind, message.Text)
		} else {
			sendCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
			if sender, ok := m.sender.(ReportSender); ok && !message.ReportStart.IsZero() && message.ReportStart.Before(message.ReportEnd) {
				err = sender.SendMessageWithReport(sendCtx, m.config.ChatID, message.Text, m.config.SourceID+"|"+m.config.Project, message.ReportStart, message.ReportEnd)
			} else {
				err = m.sender.SendMessage(sendCtx, m.config.ChatID, message.Text)
			}
			cancel()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			message.Attempts++
			delay := min(time.Minute*time.Duration(1<<min(message.Attempts-1, 5)), 30*time.Minute)
			var apiError *telegram.APIError
			if errors.As(err, &apiError) {
				if apiError.RetryAfter > delay {
					delay = apiError.RetryAfter
				}
				if apiError.Code == 400 || apiError.Code == 401 || apiError.Code == 403 {
					delay = 24 * time.Hour
				}
			}
			// retry_after начинается после ответа Telegram, а не до запроса Loki.
			message.NextTry = time.Now().UTC().Add(delay)
			m.state.TelegramAfter = message.NextTry
			fmt.Fprintln(m.diagnostic, "Telegram: доставка не подтверждена; сообщение сохранено. Проверьте токен, chat_id и права бота. Повтор после", message.NextTry.Format(time.RFC3339))
			// При проблеме Telegram не шлем остальные сообщения в тот же цикл.
			if err := m.saveState(); err != nil {
				return err
			}
			break
		}
		if !m.config.DryRun {
			kind := map[string]string{"report": "сводка", "alert": "ошибки", "source": "состояние Loki", "activity": "активность логов"}[message.Kind]
			fmt.Fprintf(m.output, "Telegram: %s — отправка подтверждена\n", kind)
		}
		if message.Kind == "alert" {
			m.markAlertsDelivered(time.Now().UTC())
		}
		if message.Kind == "source" || message.Kind == "activity" {
			m.state.LastHealth = now
			for j := range m.state.Pending {
				if m.state.Pending[j].Kind == "source" || m.state.Pending[j].Kind == "activity" {
					m.state.Pending[j].NextTry = now.Add(m.config.Cooldown)
				}
			}
		}
		m.state.Pending = append(m.state.Pending[:i], m.state.Pending[i+1:]...)
		if err := m.saveState(); err != nil {
			return err
		}
	}
	return nil
}

// Короткое сообщение описывает весь период; перечень ID остаётся в TXT по кнопке.
func (m *Monitor) summaryText(snapshot Snapshot, start, end time.Time, alert bool) string {
	var out strings.Builder
	title := "📋 Сводка заказов"
	if alert {
		title = "🔴 Заказы с ошибкой"
	}
	// В пределах одного дня дату достаточно показать один раз; границы периода сохраняем точно.
	start, end = start.UTC(), end.UTC()
	endFormat := "02.01.2006 15:04:05"
	if start.Format("02.01.2006") == end.Format("02.01.2006") {
		endFormat = "15:04:05"
	}
	fmt.Fprintf(&out, "%s · %s\n\nПериод: %s — %s UTC\n\n", title, safe(m.config.Project), start.Format("02.01.2006 15:04:05"), end.Format(endFormat))
	out.WriteString(snapshot.CoverageText() + "\n")
	writeOrderCounts(&out, snapshot)
	writeErrorCategories(&out, snapshot, m.config.ResellerNames)
	if m.state.NoLogs && snapshot.Coverage.Known && len(snapshot.Coverage.Gaps) == 0 {
		out.WriteString("\nЛоги не поступают; проверьте трафик и доставку.\n")
	}
	out.WriteString("\nРеселлеры и все ID заказов — в TXT по кнопке «За этот период».\nБез результата: в этом периоде нет подтверждённого исхода, это не ошибка.")
	return out.String()
}

func writeErrorCategories(out *strings.Builder, snapshot Snapshot, names map[string]string) {
	type category struct {
		orders    map[string]string
		resellers map[string]map[string]bool
		withoutID int
	}
	categories := make(map[string]*category)
	for _, issue := range snapshot.Issues {
		if snapshot.IsResolved(issue) {
			continue
		}
		current := categories[issue.Kind]
		if current == nil {
			current = &category{orders: make(map[string]string), resellers: make(map[string]map[string]bool)}
			categories[issue.Kind] = current
		}
		if issue.OrderID == "" {
			current.withoutID += issue.Count
			continue
		}
		current.orders[issue.OrderID] = issue.OrderType
		reseller := issue.ResellerID
		if issue.ResellerConflict {
			reseller = "\x00conflict"
		}
		if current.resellers[reseller] == nil {
			current.resellers[reseller] = make(map[string]bool)
		}
		current.resellers[reseller][issue.OrderID] = true
	}
	out.WriteString("\nОшибки за период (количество заказов):\n")
	if len(categories) == 0 {
		out.WriteString("Актуальных ошибок не обнаружено.\n")
		return
	}
	// Все категории обязательны. Длинный перечень реселлеров остаётся в TXT целиком.
	kinds := []string{"order_provision_error_timeout", "order_create_error_not_found", "order_create_error_renewal_block_period", "order_create_error_trial_lasts", "other_error"}
	resellerBudget := 1300
	for _, kind := range kinds {
		current := categories[kind]
		if current == nil {
			continue
		}
		// Запись без ID — не отдельный заказ: не показываем для неё вводящий в заблуждение ноль.
		if len(current.orders) > 0 {
			fmt.Fprintf(out, "\n• %s — %d\n", kindText(kind), len(current.orders))
		} else {
			fmt.Fprintf(out, "\n• %s\n", kindText(kind))
		}
		counts := map[string]int{}
		for _, orderType := range current.orders {
			counts[orderType]++
		}
		var types []string
		for _, orderType := range []string{"new", "renew", "cancel", "unknown"} {
			if counts[orderType] == 0 {
				continue
			}
			label := orderType
			if label == "unknown" {
				label = "тип не указан"
			}
			types = append(types, fmt.Sprintf("%s: %d", label, counts[orderType]))
		}
		if len(types) > 0 {
			fmt.Fprintf(out, "  %s\n", strings.Join(types, " · "))
		}
		if current.withoutID > 0 {
			fmt.Fprintf(out, "  Записей без ID заказа: %d (не входят в число заказов)\n", current.withoutID)
		}
		ids := make([]string, 0, len(current.resellers))
		known := 0
		for id := range current.resellers {
			ids = append(ids, id)
			if id != "" && id != "\x00conflict" {
				known++
			}
		}
		sort.Strings(ids)
		var resellers strings.Builder
		for _, id := range ids {
			label := "ID: " + id
			switch {
			case id == "":
				label = "Реселлер не определён"
			case id == "\x00conflict":
				label = "Конфликт ID реселлера"
			case names[id] != "":
				label = safe(names[id]) + " (ID: " + id + ")"
			}
			fmt.Fprintf(&resellers, "  %s — %d\n", label, len(current.resellers[id]))
		}
		if size := len([]rune(resellers.String())); len(ids) <= 2 && size <= resellerBudget {
			out.WriteString(resellers.String())
			resellerBudget -= size
		} else {
			fmt.Fprintf(out, "  Реселлеров: %d · названия и ID — в TXT\n", known)
			if count := len(current.resellers[""]); count > 0 {
				fmt.Fprintf(out, "  Реселлер не определён: %d заказов\n", count)
			}
			if count := len(current.resellers["\x00conflict"]); count > 0 {
				fmt.Fprintf(out, "  Конфликт ID реселлера: %d заказов\n", count)
			}
		}
	}
	out.WriteString("\nОдин заказ может иметь несколько видов ошибок; в шапке он учтён один раз.\n")
}

func writeOrderCounts(out *strings.Builder, snapshot Snapshot) {
	fmt.Fprintf(out, "📦 Всего заказов: %d\n✅ Успешно: %d\n🔴 С ошибкой: %d\n⏳ Без результата: %d\n", snapshot.Orders, snapshot.OrdersSucceeded, snapshot.OrdersWithErrors, snapshot.OrdersOther)
	if len(snapshot.ByType) > 0 {
		out.WriteString("\nПо типам заказов\n")
	}
	for _, counts := range snapshot.ByType {
		name := counts.Type
		if name == "unknown" {
			name = "тип не указан"
		}
		fmt.Fprintf(out, "%s — всего %d\n  ✅ %d · 🔴 %d · ⏳ %d\n", name, counts.Total, counts.Succeeded, counts.WithErrors, counts.Other)
	}

}

func (m *Monitor) unavailableReport(now time.Time) string {
	last := "еще нет"
	if !m.state.LastComplete.IsZero() {
		last = m.state.LastComplete.Format(time.RFC3339)
	}
	return "📋 Сводка недоступна · " + safe(m.config.Project) + "\nВремя: " + now.Format(time.RFC3339) + "\nПоследнее полное окно: " + last + "\nТекущий сбор не подтвержден. Нулевое число ошибок или отсутствие логов не утверждается."
}

func kindText(kind string) string {
	switch kind {
	case "order_create_error_not_found":
		return "Заказ не найден"
	case "order_provision_error_timeout":
		return "Таймаут подключения"
	case "order_create_error_still_provisioning":
		return "Заказ ещё обрабатывается"
	case "order_create_error_renewal_block_period":
		return "Продление запрещено в период блокировки"
	case "order_create_error_trial_lasts":
		return "Пробный период ещё не завершён"
	default:
		return "Другие / нераспознанные ошибки"
	}
}

func durationText(value time.Duration) string {
	if value%time.Hour == 0 {
		return fmt.Sprintf("%d ч", value/time.Hour)
	}
	if value%time.Minute == 0 {
		return fmt.Sprintf("%d мин", value/time.Minute)
	}
	return value.String()
}

func safe(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	return limitText(value, 100)
}

func limitText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit-1]) + "…"
	}
	return value
}

// windowStart ограничивает автоматический анализ данными текущего запуска.
// Предпросмотр остаётся отдельной проверкой выбранного окна без записи в базу.
func (m *Monitor) windowStart(end time.Time) time.Time {
	start := end.Add(-m.config.Window)
	if !m.config.DryRun && start.Before(m.config.SessionStart) {
		start = m.config.SessionStart
	}
	return start
}
