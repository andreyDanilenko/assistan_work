// Package storage хранит исходные события в одном локальном файле SQLite.
package storage

import (
	"database/sql"
	"time"

	"loki-analyzer/internal/model"
)

// Retention фиксирует предельный возраст сохраняемых событий, а не время последнего чтения.
const Retention = 48 * time.Hour

// Query задаёт источник, проект и полуоткрытый период [Start, End) для чтения.
type Query = model.LogRange

// Stats различает строки БД и реальные одинаковые события с сохраненной кратностью.
// У пустой базы Oldest и Newest равны нулевому времени.
type Stats struct {
	Rows, Records  int64
	Oldest, Newest time.Time
}

type Store struct{ db *sql.DB }
