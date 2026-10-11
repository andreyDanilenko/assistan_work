package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxStateBytes = 1 << 20
const maxAlertGroups = 512
const maxCooldownGroups = 2048

func (m *Monitor) binding() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", m.config.SourceID, m.config.Project, m.config.ChatID)))
	return hex.EncodeToString(sum[:])
}

// openState запрещает два процесса с одним файлом. После аварийного завершения
// оставшийся lock удаляет оператор, предварительно убедившись, что процесс остановлен.
func (m *Monitor) openState() (func(), error) {
	m.state = State{Version: 1, Binding: m.binding()}
	if m.config.DryRun {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(m.config.StateFile), 0700); err != nil {
		return nil, errors.New("не удалось создать папку состояния")
	}
	lockName := m.config.StateFile + ".lock"
	lock, err := os.OpenFile(lockName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("файл состояния занят или недоступен; проверьте процесс и оставшийся .lock")
	}
	fmt.Fprintln(lock, os.Getpid())
	lock.Close()
	release := func() { _ = os.Remove(lockName) }
	if err := m.loadState(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (m *Monitor) loadState() error {
	file, err := os.Open(m.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("не удалось открыть состояние монитора")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return errors.New("файл состояния должен быть обычным файлом не более 1 МиБ")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil || len(body) > maxStateBytes {
		return errors.New("не удалось прочитать состояние монитора")
	}
	var state State
	if json.Unmarshal(body, &state) != nil || state.Version != 1 || len(state.Pending) > 4 || len(state.AlertIssues) > maxAlertGroups || len(state.Alerted) > maxCooldownGroups || state.AlertDropped < 0 || state.CooldownEvicted < 0 {
		return errors.New("повреждено состояние монитора; автоматический сброс отключен")
	}
	if state.Binding != m.binding() {
		return errors.New("файл состояния относится к другому источнику, проекту или чату; выберите другой WATCH_STATE_FILE")
	}
	for _, message := range state.Pending {
		validPeriod := message.ReportStart.IsZero() && message.ReportEnd.IsZero() ||
			!message.ReportStart.IsZero() && message.ReportStart.Before(message.ReportEnd) &&
				message.ReportEnd.Sub(message.ReportStart) <= 48*time.Hour && (message.Kind == "alert" || message.Kind == "report")
		if len([]rune(message.Text)) > 4000 || message.Attempts < 0 || !validPeriod {
			return errors.New("неверное сообщение в сохраненной очереди")
		}
	}
	m.state = state
	if m.config.ReportOnly {
		// Переход на сводки не должен доставить старое отдельное уведомление.
		m.removePending("alert")
		m.state.AlertIssues, m.state.Alerted = nil, nil
		m.state.LastAlert = time.Time{}
		m.state.AlertDropped, m.state.CooldownEvicted = 0, 0
		if m.state.LastReportEnd.IsZero() {
			m.removePending("report")
			m.state.LastReport = time.Time{}
		}
	}
	return nil
}

// saveState сначала синхронизирует временный файл, затем заменяет состояние целиком.
// Ошибка сохранения останавливает монитор до отправки, чтобы не потерять антиспам.
func (m *Monitor) saveState() error {
	if m.config.DryRun {
		return nil
	}
	body, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil || len(body) > maxStateBytes {
		return errors.New("состояние монитора превышает допустимый размер")
	}
	file, err := os.CreateTemp(filepath.Dir(m.config.StateFile), ".watch-*")
	if err != nil {
		return errors.New("не удалось сохранить состояние монитора")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, m.config.StateFile)
	}
	if err != nil {
		return errors.New("не удалось атомарно сохранить состояние монитора")
	}
	return nil
}
