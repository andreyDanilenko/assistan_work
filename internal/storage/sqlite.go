package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"loki-analyzer/internal/model"

	_ "modernc.org/sqlite"
)

const applicationID = 0x4c4f4b49 // LOKI: отличаем свой файл от других SQLite-баз.
const createEvents = `CREATE TABLE log_events (
 identity TEXT PRIMARY KEY NOT NULL,
 source_id TEXT NOT NULL,
 project TEXT NOT NULL,
 timestamp_ns INTEGER NOT NULL,
 received_at_ns INTEGER NOT NULL,
 raw_line TEXT NOT NULL,
 labels_json TEXT NOT NULL,
 metadata_json TEXT NOT NULL,
 occurrences INTEGER NOT NULL CHECK (occurrences > 0)
)`
const createTimeIndex = `CREATE INDEX log_events_timestamp ON log_events(timestamp_ns)`

// Open создает файл и начальную схему. Произвольные URI, память и ссылки не принимаются.
// Компонент получает путь от main и не читает окружение или токены.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename, err := prepareFile(path)
	if err != nil {
		return nil, err
	}
	address := url.URL{Scheme: "file", Path: filepath.ToSlash(filename)}
	params := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(5000)", "cache_size(-8192)", "trusted_schema(OFF)", "synchronous(FULL)", "secure_delete(ON)", "temp_store(MEMORY)"}}
	address.RawQuery = params.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, errors.New("не удалось открыть SQLite")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	// Права существующего файла меняем только после подтверждения своей схемы.
	if err := os.Chmod(filename, 0600); err != nil {
		db.Close()
		return nil, errors.New("не удалось ограничить доступ к SQLite")
	}
	return store, nil
}

func prepareFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" || path == ":memory:" || strings.HasPrefix(strings.ToLower(path), "file:") || strings.ContainsRune(path, 0) {
		return "", errors.New("для SQLite нужен обычный путь к файлу")
	}
	filename, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("не удалось определить путь SQLite")
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return "", errors.New("не удалось создать папку SQLite")
	}
	// Системные ссылки в родительском пути раскрываем; сам файл не может быть ссылкой.
	directory, err := filepath.EvalSymlinks(filepath.Dir(filename))
	if err != nil {
		return "", errors.New("не удалось проверить папку SQLite")
	}
	filename = filepath.Join(directory, filepath.Base(filename))
	info, err := os.Lstat(filename)
	flags := os.O_RDWR
	if errors.Is(err, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("SQLite должен быть обычным файлом, не ссылкой или каталогом")
	}
	file, err := os.OpenFile(filename, flags, 0600)
	if err != nil {
		return "", errors.New("не удалось создать или открыть файл SQLite")
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !actual.Mode().IsRegular() || info != nil && !os.SameFile(info, actual) {
		return "", errors.New("файл SQLite изменился при открытии")
	}
	if info == nil {
		if err := file.Chmod(0600); err != nil {
			return "", errors.New("не удалось ограничить доступ к SQLite")
		}
	}
	return filename, nil
}

func (s *Store) initialize(ctx context.Context) error {
	version, err := inspectSchemaVersion(ctx, s.db)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return safeError(ctx, "не удалось настроить SQLite")
	}
	if version == 2 {
		return nil
	}
	if version == 0 {
		// Режим освобождения страниц устанавливается до первой таблицы.
		if _, err := s.db.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return safeError(ctx, "не удалось настроить очистку SQLite")
		}
	}
	tx, err := beginWrite(ctx, s.db)
	if err != nil {
		return safeError(ctx, "не удалось создать схему SQLite")
	}
	defer tx.Rollback()
	statements := []string{}
	if version == 0 {
		statements = append(statements, createEvents, createTimeIndex, "PRAGMA application_id="+strconv.Itoa(applicationID))
	}
	statements = append(statements, createScopeIndex, createProgress, createRanges, "PRAGMA user_version=2")
	for _, query := range statements {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return safeError(ctx, "не удалось создать схему SQLite")
		}
	}
	if err := tx.Commit(); err != nil {
		return safeError(ctx, "не удалось сохранить схему SQLite")
	}
	return nil
}

type schemaReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Версия 1 читается без миграции; только Open добавляет сведения о сборе.
func inspectSchema(ctx context.Context, db schemaReader) (bool, error) {
	version, err := inspectSchemaVersion(ctx, db)
	return version == 0, err
}

func inspectSchemaVersion(ctx context.Context, db schemaReader) (int, error) {
	var appID, version, objects int
	for query, target := range map[string]*int{
		"PRAGMA application_id": &appID,
		"PRAGMA user_version":   &version,
		"SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'": &objects,
	} {
		if err := db.QueryRowContext(ctx, query).Scan(target); err != nil {
			return 0, safeError(ctx, "не удалось прочитать схему SQLite")
		}
	}
	if appID == 0 && version == 0 && objects == 0 {
		return 0, nil
	}
	expected := map[string]string{"log_events": createEvents, "log_events_timestamp": createTimeIndex}
	if version == 2 {
		expected["log_events_scope_time"] = createScopeIndex
		expected["collection_progress"] = createProgress
		expected["collection_ranges"] = createRanges
	}
	if appID != applicationID || (version != 1 && version != 2) || objects != len(expected) {
		return 0, errors.New("файл SQLite принадлежит другому приложению или имеет неподдерживаемую схему")
	}
	var vacuum int
	if err := db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&vacuum); err != nil || vacuum != 2 {
		return 0, safeError(ctx, "SQLite требует режим incremental auto_vacuum")
	}
	for name, definition := range expected {
		var actual string
		if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE name = ?", name).Scan(&actual); err != nil || strings.Join(strings.Fields(actual), " ") != strings.Join(strings.Fields(definition), " ") {
			return 0, safeError(ctx, "схема SQLite не соответствует версии приложения")
		}
	}
	return version, nil
}

// ReadLogs читает существующую базу без создания, очистки или изменения её настроек.
// Соединение и транзакция закрываются до возврата данных вызывающему коду.
func ReadLogs(ctx context.Context, path string, query Query) ([]model.LogRecord, error) {
	records, _, err := ReadRange(ctx, path, query)
	return records, err
}

// ReadRange читает события и подтверждённое покрытие из одного снимка.
func ReadRange(ctx context.Context, path string, query Query) ([]model.LogRecord, model.Coverage, error) {
	if err := ctx.Err(); err != nil {
		return nil, model.Coverage{}, err
	}
	if query.Project == "" || query.SourceID == "" {
		return nil, model.Coverage{}, errors.New("для отчёта нужны проект и источник логов")
	}
	if !query.Start.Before(query.End) || query.End.Sub(query.Start) > Retention {
		return nil, model.Coverage{}, errors.New("период отчёта должен быть больше нуля и не больше 48 часов")
	}
	for _, at := range []time.Time{query.Start, query.End} {
		if !time.Unix(0, at.UnixNano()).Equal(at) {
			return nil, model.Coverage{}, errors.New("время отчёта не помещается в наносекунды Unix")
		}
	}
	if strings.TrimSpace(path) == "" || path == ":memory:" || strings.HasPrefix(strings.ToLower(path), "file:") || strings.ContainsRune(path, 0) {
		return nil, model.Coverage{}, errors.New("для SQLite нужен обычный путь к файлу")
	}
	filename, err := filepath.Abs(path)
	if err != nil {
		return nil, model.Coverage{}, errors.New("не удалось определить путь SQLite")
	}
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, model.Coverage{}, errors.New("база логов ещё не создана; сначала запустите watch")
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, model.Coverage{}, errors.New("SQLite должен быть существующим обычным файлом")
	}
	address := url.URL{Scheme: "file", Path: filepath.ToSlash(filename)}
	address.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)", "trusted_schema(OFF)", "query_only(ON)"}}.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось открыть SQLite для отчёта")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// Схема, объём, события и покрытие относятся к одному снимку SQLite.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось начать чтение отчёта")
	}
	defer tx.Rollback()
	version, err := inspectSchemaVersion(ctx, tx)
	if err != nil {
		return nil, model.Coverage{}, err
	}
	if version == 0 {
		return nil, model.Coverage{}, errors.New("в файле нет базы логов; сначала запустите watch")
	}
	const selection = ` FROM log_events WHERE source_id = ? AND project = ? AND timestamp_ns >= ? AND timestamp_ns < ?`
	args := []any{query.SourceID, query.Project, query.Start.UnixNano(), query.End.UnixNano()}
	const maxRecords, maxBytes = 100000, 64 << 20
	var count, size int64
	err = tx.QueryRowContext(ctx, `SELECT coalesce(sum(occurrences),0), coalesce(sum(occurrences *
 (length(CAST(raw_line AS BLOB)) + length(CAST(labels_json AS BLOB)) + length(CAST(metadata_json AS BLOB)))),0)`+selection, args...).Scan(&count, &size)
	if err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось оценить объём отчёта; сократите период")
	}
	if count > maxRecords || size > maxBytes || count < 0 || size < 0 {
		return nil, model.Coverage{}, errors.New("отчёт превышает 100000 записей или 64 МиБ; сократите период")
	}
	rows, err := tx.QueryContext(ctx, `SELECT timestamp_ns, raw_line, labels_json, metadata_json, occurrences`+selection+` ORDER BY timestamp_ns, identity`, args...)
	if err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось прочитать логи для отчёта")
	}
	defer rows.Close()
	records := make([]model.LogRecord, 0, int(count))
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, model.Coverage{}, err
		}
		entry := model.LogRecord{Project: query.Project}
		var stamp, occurrences int64
		var labels, metadata string
		if err := rows.Scan(&stamp, &entry.Line, &labels, &metadata, &occurrences); err != nil {
			return nil, model.Coverage{}, safeError(ctx, "не удалось прочитать запись отчёта")
		}
		if json.Unmarshal([]byte(labels), &entry.Labels) != nil || json.Unmarshal([]byte(metadata), &entry.Metadata) != nil {
			return nil, model.Coverage{}, errors.New("метки или metadata в базе логов повреждены")
		}
		entry.Timestamp = time.Unix(0, stamp).UTC()
		// Повторно прочитанное окно не удваивает события; возвращаем сохранённую кратность.
		for i := int64(0); i < occurrences; i++ {
			records = append(records, entry)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось завершить чтение отчёта")
	}
	if err := rows.Close(); err != nil {
		return nil, model.Coverage{}, safeError(ctx, "не удалось завершить чтение отчёта")
	}
	coverage := model.Coverage{Gaps: []model.TimeRange{{Start: query.Start, End: query.End}}}
	if version == 2 {
		coverage, err = readCoverage(ctx, tx, query)
		if err != nil {
			return nil, model.Coverage{}, err
		}
	}
	return records, coverage, nil
}

// Save принимает только полный ответ окна: так кратность одинаковых событий достоверна.
// Повтор окна увеличивает occurrences только до нового наблюдаемого максимума.
func (s *Store) Save(ctx context.Context, sourceID string, records []model.LogRecord, now time.Time) error {
	if sourceID == "" {
		return errors.New("для сохранения нужен идентификатор источника")
	}
	cutoff, err := cutoffNS(now)
	if err != nil {
		return err
	}
	if _, err := s.Prune(ctx, now); err != nil {
		return err
	}
	batch, err := encodeRecords(ctx, sourceID, records, now, cutoff)
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	tx, err := beginWrite(ctx, s.db)
	if err != nil {
		return safeError(ctx, "не удалось начать запись логов")
	}
	defer tx.Rollback()
	if err := insertRecords(ctx, tx.Tx, sourceID, batch, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return safeError(ctx, "не удалось завершить запись логов")
	}
	return nil
}

type storedEvent struct {
	record           model.LogRecord
	labels, metadata string
	count            int64
}

func encodeRecords(ctx context.Context, sourceID string, records []model.LogRecord, now time.Time, cutoff int64) (map[string]*storedEvent, error) {
	batch := make(map[string]*storedEvent)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stamp := record.Timestamp.UnixNano()
		if !time.Unix(0, stamp).Equal(record.Timestamp) {
			return nil, errors.New("время события не помещается в наносекунды Unix")
		}
		// Поздние старые события не возвращаются в базу; будущие даты не сохраняем.
		if stamp < cutoff || record.Timestamp.After(now) {
			continue
		}
		if record.Project == "" {
			return nil, errors.New("для сохранения события нужен проект")
		}
		labels, err := json.Marshal(record.Labels)
		if err != nil {
			return nil, errors.New("не удалось сохранить метки события")
		}
		metadata, err := json.Marshal(record.Metadata)
		if err != nil {
			return nil, errors.New("не удалось сохранить metadata события")
		}
		// JSON сортирует ключи карт; длины частей исключают неоднозначность разделителей.
		hash := sha256.New()
		for _, part := range []string{sourceID, record.Project, strconv.FormatInt(stamp, 10), record.Line, string(labels), string(metadata)} {
			binary.Write(hash, binary.BigEndian, uint64(len(part)))
			hash.Write([]byte(part))
		}
		key := hex.EncodeToString(hash.Sum(nil))
		if previous := batch[key]; previous != nil {
			previous.count++
			continue
		}
		batch[key] = &storedEvent{record: record, labels: string(labels), metadata: string(metadata), count: 1}
	}
	return batch, nil
}

func insertRecords(ctx context.Context, tx *sql.Tx, sourceID string, batch map[string]*storedEvent, now time.Time) error {
	statement, err := tx.PrepareContext(ctx, `INSERT INTO log_events (identity, source_id, project, timestamp_ns, received_at_ns, raw_line, labels_json, metadata_json, occurrences)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT(identity) DO UPDATE SET occurrences = max(log_events.occurrences, excluded.occurrences)`)
	if err != nil {
		return safeError(ctx, "не удалось подготовить запись логов")
	}
	defer statement.Close()
	for key, entry := range batch {
		if _, err := statement.ExecContext(ctx, key, sourceID, entry.record.Project, entry.record.Timestamp.UnixNano(), now.UnixNano(), entry.record.Line, entry.labels, entry.metadata, entry.count); err != nil {
			return safeError(ctx, "не удалось сохранить логи")
		}
	}
	return nil
}

// Prune удаляет строки старше 48 часов короткими порциями. Граница 48 часов включена.
// Возвращает число удаленных строк БД; их occurrences могли быть больше единицы.
func (s *Store) Prune(ctx context.Context, now time.Time) (int64, error) {
	cutoff, err := cutoffNS(now)
	if err != nil {
		return 0, err
	}
	var removed int64
	for {
		tx, err := beginWrite(ctx, s.db)
		if err != nil {
			return removed, safeError(ctx, "не удалось начать очистку логов")
		}
		count, err := pruneBatch(ctx, tx.Tx, cutoff)
		if err != nil {
			tx.Rollback()
			return removed, err
		}
		if err := trimCoverage(ctx, tx.Tx, cutoff); err != nil {
			tx.Rollback()
			return removed, err
		}
		if err := tx.Commit(); err != nil {
			return removed, safeError(ctx, "не удалось завершить очистку логов")
		}
		removed += count
		if count < 1000 {
			break
		}
	}
	// Полный VACUUM не нужен: освобождаем только свободные страницы, по 1000 за шаг.
	previousFree := int64(-1)
	for {
		var free int64
		if err := s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
			return removed, safeError(ctx, "не удалось проверить свободное место SQLite")
		}
		if free == 0 {
			return removed, nil
		}
		if previousFree >= 0 && free >= previousFree {
			return removed, errors.New("SQLite не освобождает страницы; проверьте режим auto_vacuum")
		}
		previousFree = free
		rows, err := s.db.QueryContext(ctx, "PRAGMA incremental_vacuum(1000)")
		if err != nil {
			return removed, safeError(ctx, "не удалось освободить место SQLite")
		}
		for rows.Next() {
		} // Некоторые драйверы освобождают страницы при каждом шаге результата.
		err = rows.Err()
		rows.Close()
		if err != nil {
			return removed, safeError(ctx, "не удалось завершить освобождение места SQLite")
		}
	}
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var result Stats
	var oldest, newest sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT count(*), coalesce(sum(occurrences),0), min(timestamp_ns), max(timestamp_ns) FROM log_events").Scan(&result.Rows, &result.Records, &oldest, &newest); err != nil {
		return Stats{}, safeError(ctx, "не удалось прочитать статистику SQLite")
	}
	if oldest.Valid {
		result.Oldest, result.Newest = time.Unix(0, oldest.Int64).UTC(), time.Unix(0, newest.Int64).UTC()
	}
	return result, nil
}

func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return errors.New("не удалось закрыть SQLite")
	}
	return nil
}

func cutoffNS(now time.Time) (int64, error) {
	cutoff := now.Add(-Retention)
	if !time.Unix(0, now.UnixNano()).Equal(now) || !time.Unix(0, cutoff.UnixNano()).Equal(cutoff) {
		return 0, errors.New("время хранения не помещается в наносекунды Unix")
	}
	return cutoff.UnixNano(), nil
}

func safeError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}
