package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"loki-analyzer/internal/model"
)

const createScopeIndex = `CREATE INDEX log_events_scope_time ON log_events(source_id, project, timestamp_ns)`
const createProgress = `CREATE TABLE collection_progress (
 source_id TEXT NOT NULL,
 project TEXT NOT NULL,
 cursor_ns INTEGER NOT NULL,
 PRIMARY KEY (source_id, project)
)`
const createRanges = `CREATE TABLE collection_ranges (
 source_id TEXT NOT NULL,
 project TEXT NOT NULL,
 start_ns INTEGER NOT NULL,
 end_ns INTEGER NOT NULL CHECK (end_ns > start_ns),
 PRIMARY KEY (source_id, project, start_ns)
)`

func validateRange(query model.LogRange) error {
	if query.SourceID == "" || query.Project == "" {
		return errors.New("для периода нужны источник и проект")
	}
	if !query.Start.Before(query.End) || query.End.Sub(query.Start) > Retention {
		return errors.New("период должен быть больше нуля и не больше 48 часов")
	}
	for _, at := range []time.Time{query.Start, query.End} {
		if !time.Unix(0, at.UnixNano()).Equal(at) {
			return errors.New("время периода не помещается в наносекунды Unix")
		}
	}
	return nil
}

// Resume фиксирует начальную точку до первого сетевого запроса. Следующий запуск
// продолжает её даже при новом скользящем окне. Просроченную историю не подтверждаем.
func (s *Store) Resume(ctx context.Context, query model.LogRange, now time.Time) (time.Time, error) {
	if err := validateRange(query); err != nil {
		return time.Time{}, err
	}
	cutoff, err := cutoffNS(now)
	if err != nil {
		return time.Time{}, err
	}
	tx, err := beginWrite(ctx, s.db)
	if err != nil {
		return time.Time{}, safeError(ctx, "не удалось прочитать прогресс сбора")
	}
	defer tx.Rollback()
	if err := initProgress(ctx, tx.Tx, query, cutoff); err != nil {
		return time.Time{}, err
	}
	var cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT cursor_ns FROM collection_progress WHERE source_id = ? AND project = ?`, query.SourceID, query.Project).Scan(&cursor); err != nil {
		return time.Time{}, safeError(ctx, "не удалось прочитать прогресс сбора")
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, safeError(ctx, "не удалось сохранить начало сбора")
	}
	return time.Unix(0, cursor).UTC(), nil
}

func initProgress(ctx context.Context, tx *sql.Tx, query model.LogRange, cutoff int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO collection_progress (source_id, project, cursor_ns) VALUES (?, ?, max(?, ?))
 ON CONFLICT(source_id, project) DO UPDATE SET cursor_ns = max(collection_progress.cursor_ns, ?)`, query.SourceID, query.Project, query.Start.UnixNano(), cutoff, cutoff)
	if err != nil {
		return safeError(ctx, "не удалось сохранить прогресс сбора")
	}
	return nil
}

// SaveRange подтверждает только целиком полученный диапазон, включая пустой.
// События, покрытие и непрерывный курсор становятся видимы одним commit.
func (s *Store) SaveRange(ctx context.Context, query model.LogRange, records []model.LogRecord, now time.Time) error {
	if err := validateRange(query); err != nil {
		return err
	}
	cutoff, err := cutoffNS(now)
	if err != nil {
		return err
	}
	if query.End.After(now) {
		return errors.New("нельзя подтвердить будущий период сбора")
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.Project != query.Project || record.Timestamp.Before(query.Start) || !record.Timestamp.Before(query.End) {
			return errors.New("событие не принадлежит сохраняемому проекту или периоду")
		}
	}
	batch, err := encodeRecords(ctx, query.SourceID, records, now, cutoff)
	if err != nil {
		return err
	}
	tx, err := beginWrite(ctx, s.db)
	if err != nil {
		return safeError(ctx, "не удалось начать запись диапазона")
	}
	defer tx.Rollback()
	// Очищаем в той же транзакции, чтобы покрытие не пережило удалённые события.
	for {
		count, err := pruneBatch(ctx, tx.Tx, cutoff)
		if err != nil {
			return err
		}
		if count < 1000 {
			break
		}
	}
	if err := trimCoverage(ctx, tx.Tx, cutoff); err != nil {
		return err
	}
	if err := insertRecords(ctx, tx.Tx, query.SourceID, batch, now); err != nil {
		return err
	}
	if err := initProgress(ctx, tx.Tx, query, cutoff); err != nil {
		return err
	}
	start, end := max(query.Start.UnixNano(), cutoff), query.End.UnixNano()
	if start < end {
		if err := mergeRange(ctx, tx.Tx, query.SourceID, query.Project, start, end); err != nil {
			return err
		}
		// Диапазоны объединены, поэтому курсор может пересечь только один интервал.
		_, err := tx.ExecContext(ctx, `UPDATE collection_progress SET cursor_ns = coalesce(
 (SELECT max(end_ns) FROM collection_ranges WHERE source_id = ? AND project = ? AND start_ns <= cursor_ns AND end_ns > cursor_ns), cursor_ns)
 WHERE source_id = ? AND project = ?`, query.SourceID, query.Project, query.SourceID, query.Project)
		if err != nil {
			return safeError(ctx, "не удалось продвинуть прогресс сбора")
		}
	}
	if err := tx.Commit(); err != nil {
		return safeError(ctx, "не удалось завершить запись диапазона")
	}
	return nil
}

func mergeRange(ctx context.Context, tx *sql.Tx, source, project string, start, end int64) error {
	var oldStart, oldEnd sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT min(start_ns), max(end_ns) FROM collection_ranges
 WHERE source_id = ? AND project = ? AND start_ns <= ? AND end_ns >= ?`, source, project, end, start).Scan(&oldStart, &oldEnd); err != nil {
		return safeError(ctx, "не удалось прочитать покрытие диапазона")
	}
	if oldStart.Valid {
		start, end = min(start, oldStart.Int64), max(end, oldEnd.Int64)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM collection_ranges WHERE source_id = ? AND project = ? AND start_ns <= ? AND end_ns >= ?`, source, project, end, start); err != nil {
		return safeError(ctx, "не удалось объединить покрытие диапазона")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO collection_ranges (source_id, project, start_ns, end_ns) VALUES (?, ?, ?, ?)`, source, project, start, end); err != nil {
		return safeError(ctx, "не удалось сохранить покрытие диапазона")
	}
	return nil
}

// Latest читает одно время через индекс, не выгружая накопленную историю.
func (s *Store) Latest(ctx context.Context, sourceID, project string, end time.Time) (time.Time, error) {
	if sourceID == "" || project == "" || !time.Unix(0, end.UnixNano()).Equal(end) {
		return time.Time{}, errors.New("для последнего события нужны источник, проект и корректная граница времени")
	}
	var stamp sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(timestamp_ns) FROM log_events WHERE source_id = ? AND project = ? AND timestamp_ns < ?`, sourceID, project, end.UnixNano()).Scan(&stamp); err != nil {
		return time.Time{}, safeError(ctx, "не удалось прочитать время последнего события")
	}
	if !stamp.Valid {
		return time.Time{}, nil
	}
	return time.Unix(0, stamp.Int64).UTC(), nil
}

// Coverage возвращает только подтверждённые промежутки своего источника и проекта.
func (s *Store) Coverage(ctx context.Context, query model.LogRange) (model.Coverage, error) {
	if err := validateRange(query); err != nil {
		return model.Coverage{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.Coverage{}, safeError(ctx, "не удалось начать чтение покрытия")
	}
	defer tx.Rollback()
	return readCoverage(ctx, tx, query)
}

func readCoverage(ctx context.Context, tx *sql.Tx, query model.LogRange) (model.Coverage, error) {
	const maxIntervals = 100000
	rows, err := tx.QueryContext(ctx, `SELECT start_ns, end_ns FROM collection_ranges
 WHERE source_id = ? AND project = ? AND end_ns > ? AND start_ns < ? ORDER BY start_ns LIMIT ?`, query.SourceID, query.Project, query.Start.UnixNano(), query.End.UnixNano(), maxIntervals+1)
	if err != nil {
		return model.Coverage{}, safeError(ctx, "не удалось прочитать покрытие отчёта")
	}
	defer rows.Close()
	result := model.Coverage{Known: true}
	cursor, end := query.Start.UnixNano(), query.End.UnixNano()
	count := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return model.Coverage{}, err
		}
		count++
		if count > maxIntervals {
			return model.Coverage{}, errors.New("покрытие отчёта превышает 100000 интервалов; сократите период")
		}
		var low, high int64
		if err := rows.Scan(&low, &high); err != nil {
			return model.Coverage{}, safeError(ctx, "не удалось прочитать интервал покрытия")
		}
		low, high = max(low, query.Start.UnixNano()), min(high, end)
		if low > cursor {
			result.Gaps = append(result.Gaps, model.TimeRange{Start: time.Unix(0, cursor).UTC(), End: time.Unix(0, low).UTC()})
		}
		cursor = max(cursor, high)
	}
	if err := rows.Err(); err != nil {
		return model.Coverage{}, safeError(ctx, "не удалось завершить чтение покрытия")
	}
	if cursor < end {
		result.Gaps = append(result.Gaps, model.TimeRange{Start: time.Unix(0, cursor).UTC(), End: query.End})
	}
	return result, nil
}

func pruneBatch(ctx context.Context, tx *sql.Tx, cutoff int64) (int64, error) {
	result, err := tx.ExecContext(ctx, `DELETE FROM log_events WHERE rowid IN
 (SELECT rowid FROM log_events WHERE timestamp_ns < ? ORDER BY timestamp_ns LIMIT 1000)`, cutoff)
	if err != nil {
		return 0, safeError(ctx, "не удалось удалить устаревшие логи")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, safeError(ctx, "не удалось проверить очистку логов")
	}
	return count, nil
}

func trimCoverage(ctx context.Context, tx *sql.Tx, cutoff int64) error {
	for _, query := range []string{
		`DELETE FROM collection_ranges WHERE end_ns <= ?`,
		`UPDATE collection_ranges SET start_ns = ? WHERE start_ns < ?`,
		`UPDATE collection_progress SET cursor_ns = ? WHERE cursor_ns < ?`,
	} {
		args := []any{cutoff}
		if query[0] == 'U' {
			args = append(args, cutoff)
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return safeError(ctx, "не удалось очистить просроченное покрытие")
		}
	}
	return nil
}
