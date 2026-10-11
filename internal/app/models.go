package app

import (
	"errors"
	"strings"
	"time"
)

// Command задает операцию получения данных; формат CLI-флагов сюда не передается.
type Command string

const (
	Check    Command = "check"
	Labels   Command = "labels"
	Values   Command = "values"
	Projects Command = "projects"
	Logs     Command = "logs"
	Query    Command = "query"
)

// Request описывает, какие данные получить. Настройки подключения и вывода хранятся отдельно.
type Request struct {
	Command    Command
	Label      string
	Project    string
	Expression string
	Start      time.Time
	End        time.Time
	Limit      int
}

// Validate ограничивает период и проверяет параметры, нужные именно выбранной операции.
func (r Request) Validate() error {
	if !r.Start.Before(r.End) || r.End.Sub(r.Start) > 24*time.Hour {
		return errors.New("период должен быть положительным и не более 24h")
	}
	switch r.Command {
	case Check, Labels, Projects:
		return nil
	case Values:
		if strings.TrimSpace(r.Label) == "" {
			return errors.New("укажите имя метки")
		}
	case Logs, Query:
		if r.Limit < 1 || r.Limit > 100000 {
			return errors.New("лимит должен быть от 1 до 100000")
		}
		if r.Command == Query && strings.TrimSpace(r.Expression) == "" {
			return errors.New("укажите выражение LogQL")
		}
	default:
		return errors.New("неизвестная команда")
	}
	return nil
}
