package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/report"
)

// printResponse выбирает представление уже разобранного ответа, не повторяя запрос к Loki.
func printResponse(output io.Writer, options Options, response model.Response) error {
	if options.Raw {
		return printRaw(output, response.Body)
	}
	switch options.Request.Command {
	case app.Check:
		_, err := fmt.Fprintf(output, "Доступ к Grafana и Loki работает. HTTP %d. Меток: %d.\n", response.StatusCode, len(response.Values))
		return err
	case app.Logs, app.Query:
		if response.Query == nil {
			return errors.New("missing parsed query response")
		}
		return printLogSummary(output, *response.Query)
	default:
		return printValues(output, response.Values)
	}
}

func printRaw(output io.Writer, body json.RawMessage) error {
	// --raw запрошен явно: меняем только отступы JSON, сохраняя исходные значения.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, pretty.String())
	return err
}

func printValues(output io.Writer, values []string) error {
	if len(values) == 0 {
		_, err := fmt.Fprintln(output, "Нет значений за выбранный период.")
		return err
	}
	// Сортируем копию, чтобы оформление ответа не меняло данные сервиса.
	values = append([]string(nil), values...)
	sort.Strings(values)
	for _, value := range values {
		// Экранируем управляющие символы: значение метки не должно выполнять команды терминала.
		if _, err := fmt.Fprintln(output, strconv.Quote(value)); err != nil {
			return err
		}
	}
	return nil
}

// printLogSummary по умолчанию выводит только объем и время, без текста логов и меток.
func printLogSummary(output io.Writer, response model.LokiQueryResponse) error {
	count, first, last := logSummary(response.Data.Result)
	if _, err := fmt.Fprintf(output, "Потоков: %d | Записей в ответе: %d\n", len(response.Data.Result), count); err != nil {
		return err
	}
	if count > 0 {
		if _, err := fmt.Fprintf(output, "Первое: %s\nПоследнее: %s\n", first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(output, "Для просмотра исходных записей добавьте --raw. Анализ не выполнялся.")
	return err
}

// logSummary ищет крайние даты во всех потоках: ответ не обязан быть отсортирован целиком.
func logSummary(streams []model.LokiStream) (int, time.Time, time.Time) {
	count := 0
	var first, last time.Time
	for _, stream := range streams {
		for _, entry := range stream.Values {
			when := time.Unix(0, entry.TimestampNS).UTC()
			if count == 0 || when.Before(first) {
				first = when
			}
			if count == 0 || when.After(last) {
				last = when
			}
			count++
		}
	}
	return count, first, last
}

// printAnalysis передает оформление общему модулю отчётов CLI и Telegram.
func printAnalysis(output io.Writer, result model.AnalysisResult, allOrders bool) error {
	return report.WriteFile(output, result, allOrders)
}

// PrintBotInfo показывает учетную запись бота после getMe; токен в эту функцию не передается.
func PrintBotInfo(output io.Writer, bot model.BotInfo) error {
	_, err := fmt.Fprintf(output, "Telegram-бот подключен. Username: %q | ID: %d | Имя: %q\n", bot.Username, bot.ID, bot.FirstName)
	return err
}

// WriteError используется и при ошибках запуска, когда сервис еще не создан.
func WriteError(output io.Writer, prefix string, err error) {
	fmt.Fprintf(output, "%s: %v\n", prefix, err)
}

// printAccessHint добавляет совет по коду HTTP, не показывая тело ответа или данные авторизации.
func printAccessHint(output io.Writer, status int) {
	var hint string
	switch status {
	case 401:
		hint = "Проверьте GRAFANA_TOKEN: токен мог истечь или быть отозван."
	case 403:
		hint = "Проверьте права сервисной учетной записи на запросы к источнику Loki и организацию."
	case 301, 302, 303, 307, 308:
		hint = "Grafana перенаправляет запрос. Проверьте адрес и доступ API через корпоративный шлюз."
	case 404:
		hint = "Проверьте GRAFANA_URL и GRAFANA_DATASOURCE_UID."
	}
	if hint != "" {
		fmt.Fprintln(output, hint)
	}
}
