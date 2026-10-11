package model

import "time"

// LogRange связывает период с конкретным источником и проектом.
type LogRange struct {
	SourceID, Project string
	Start, End        time.Time
}

// TimeRange — полуоткрытый интервал [Start, End).
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Coverage показывает, какие части отчёта подтверждены сохранёнными выгрузками.
// Полное покрытие относится к данным, доступным в Loki на момент запросов.
type Coverage struct {
	Known bool        `json:"known"`
	Gaps  []TimeRange `json:"gaps"`
}
