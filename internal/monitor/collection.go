package monitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
)

const collectionPortion = 2 * time.Minute
const maxCollectionRequests = 64
const maxPreviewRecords = 100000
const maxPreviewBytes = 64 << 20

type collectionResult struct {
	portions, records int
	previewBytes      int64
	complete          bool
	preview           []model.LogRecord // Только dry-run: рабочий сбор не накапливает историю в памяти.
}

func (m *Monitor) logRange(start, end time.Time) model.LogRange {
	return model.LogRange{SourceID: m.config.SourceID, Project: m.config.Project, Start: start, End: end}
}

// collect фиксирует каждую полностью полученную часть до следующего запроса.
// Бюджет относится ко всему циклу, включая дробление переполненных ответов.
func (m *Monitor) collect(ctx context.Context, end, now time.Time) (collectionResult, error) {
	var collected collectionResult
	cycleCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()
	start := end.Add(-m.config.Window)
	retentionStart := now.Add(-48 * time.Hour)
	if !m.config.DryRun {
		// Каждый цикл берёт только свежее окно, без перекрытия и догрузки
		// старых пропусков. Ошибка не переносит этот запрос в следующий цикл.
		start = end.Add(-m.config.Interval)
		if start.Before(m.config.SessionStart) {
			start = m.config.SessionStart
		}
	}
	if start.Before(retentionStart) {
		start = retentionStart
	}
	if !start.Before(end) {
		// В первые десять секунд ещё нет периода за защитной задержкой Loki.
		// Не создаём недопустимый диапазон и не считаем ожидание отказом.
		collected.complete = true
		return collected, nil
	}
	cursor := start
	requests := 0
	var fetch func(time.Time, time.Time) (bool, error)
	fetch = func(from, to time.Time) (bool, error) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if requests >= maxCollectionRequests || cycleCtx.Err() != nil {
			return false, nil
		}
		requests++
		result, err := m.source.FetchLogs(cycleCtx, loki.Query{Project: m.config.Project, Start: from, End: to})
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			// Повтор пока не выполняем: актуальность важнее восстановления окна.
			return false, nil
		}
		if !result.Complete {
			// Частичные строки нельзя считать доказательством покрытия. Сначала
			// сохраняем левую половину; отказ справа не удаляет уже полученные данные.
			if to.Sub(from) <= time.Nanosecond {
				return false, nil
			}
			middle := from.Add(to.Sub(from) / 2)
			ok, err := fetch(from, middle)
			if err != nil || !ok {
				return false, err
			}
			return fetch(middle, to)
		}
		if !m.config.DryRun {
			if err := m.archive.SaveRange(cycleCtx, m.logRange(from, to), result.Records, time.Now().UTC()); err != nil {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				if cycleCtx.Err() != nil {
					return false, nil
				}
				return false, errors.New("не удалось сохранить часть логов в SQLite; покрытие и уведомления не обновлены")
			}
		} else {
			// Dry-run объединяет части только в памяти, поэтому лимит должен
			// относиться ко всему предпросмотру, а не к одному ответу Loki.
			bytes := previewBytes(result.Records, maxPreviewBytes-collected.previewBytes)
			if len(result.Records) > maxPreviewRecords-len(collected.preview) || bytes > maxPreviewBytes-collected.previewBytes {
				fmt.Fprintln(m.diagnostic, "Предпросмотр остановлен: общий лимит 100000 записей или 64 МиБ превышен. Период получен не полностью; уменьшите окно.")
				return false, nil
			}
			collected.previewBytes += bytes
			collected.preview = append(collected.preview, result.Records...)
		}
		collected.portions++
		collected.records += len(result.Records)
		return true, nil
	}
	for cursor.Before(end) {
		to := minTime(cursor.Add(collectionPortion), end)
		ok, err := fetch(cursor, to)
		if err != nil || !ok {
			return collected, err
		}
		cursor = to
	}
	collected.complete = true
	return collected, nil
}

// Добавляем запас на структуры и map-элементы, не создавая JSON-копий строк.
func previewBytes(records []model.LogRecord, remaining int64) int64 {
	var size int64
	for _, record := range records {
		size += int64(len(record.Line)) + int64(len(record.Project)) + 256
		for key, value := range record.Labels {
			size += int64(len(key)) + int64(len(value)) + 64
		}
		for key, value := range record.Metadata {
			size += int64(len(key)) + int64(len(value)) + 64
		}
		if size > remaining {
			return size
		}
	}
	return size
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (m *Monitor) checkActivity(ctx context.Context, end, now time.Time) error {
	var latest time.Time
	if m.config.DryRun {
		// Нет записи покрытия, поэтому предпросмотр не делает вывода о тишине.
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()
	coverage, err := m.archive.Coverage(checkCtx, m.logRange(end.Add(-m.config.NoLogsAfter), end))
	if err != nil {
		return errors.New("не удалось проверить покрытие периода активности")
	}
	if !coverage.Known || len(coverage.Gaps) > 0 {
		return nil
	}
	latest, err = m.archive.Latest(checkCtx, m.config.SourceID, m.config.Project, end)
	if err != nil {
		return errors.New("не удалось проверить время последнего события")
	}
	noLogs := latest.IsZero() || latest.Before(end.Add(-m.config.NoLogsAfter))
	if noLogs && !m.state.NoLogs {
		m.queue("activity", fmt.Sprintf("🟡 Логи не поступают\nПроект: %s\nЗа последние %s в подтверждённом периоде нет новых записей.\nЭто может быть отсутствие трафика или остановка доставки логов. Падение сервиса не подтверждено.", safe(m.config.Project), m.config.NoLogsAfter), now)
	} else if !noLogs && m.state.NoLogs {
		m.queue("activity", "🟢 Логи снова поступают\nПроект: "+safe(m.config.Project)+"\nПоследнее событие: "+latest.Format(time.RFC3339), now)
	}
	m.state.NoLogs = noLogs
	return nil
}
