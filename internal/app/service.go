// Пакет app задает порядок действий; получение данных и анализ выполняют переданные компоненты.
package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"loki-analyzer/internal/model"
)

// LogSource описывает нужные сервису операции. Реальный клиент или тестовую замену передают снаружи.
type LogSource interface {
	GetLabels(context.Context, time.Time, time.Time) (model.Response, error)
	GetLabelValues(context.Context, string, time.Time, time.Time) (model.Response, error)
	QueryRange(context.Context, string, time.Time, time.Time, int) (model.Response, error)
}

// Config содержит настройки выборки. Адрес подключения и токен остаются у клиента Loki.
type Config struct {
	DefaultProject string
	ProjectLabel   string
}

// Service выполняет команды получения данных через переданный источник.
type Service struct {
	config Config
	source LogSource
}

// New сохраняет готовые зависимости; создание сервиса не вызывает сеть.
func New(config Config, source LogSource) *Service {
	return &Service{config: config, source: source}
}

// Execute переводит команду приложения в одну операцию источника.
func (s *Service) Execute(ctx context.Context, request Request) (model.Response, error) {
	if err := ctx.Err(); err != nil {
		return model.Response{}, err
	}
	// Проверка нужна и здесь: будущий REST сможет вызвать сервис без CLI.
	if err := request.Validate(); err != nil {
		return model.Response{}, err
	}
	switch request.Command {
	case Check, Labels:
		// Список меток одновременно проверяет доступ к Grafana и выбранному Loki.
		return s.source.GetLabels(ctx, request.Start, request.End)
	case Values:
		return s.source.GetLabelValues(ctx, request.Label, request.Start, request.End)
	case Projects:
		return s.source.GetLabelValues(ctx, s.config.ProjectLabel, request.Start, request.End)
	case Logs:
		return s.projectLogs(ctx, request)
	case Query:
		return s.source.QueryRange(ctx, request.Expression, request.Start, request.End, request.Limit)
	default:
		return model.Response{}, errors.New("неизвестная команда")
	}
}

// projectLogs использует проект из запроса, а при его отсутствии — из настроек сервиса.
func (s *Service) projectLogs(ctx context.Context, request Request) (model.Response, error) {
	project := request.Project
	if project == "" {
		project = s.config.DefaultProject
	}
	if strings.TrimSpace(project) == "" || len(project) > 4096 {
		return model.Response{}, errors.New("проект должен быть непустым и не длиннее 4096 байт")
	}
	// Экранируем имя проекта как строку, чтобы оно не могло изменить выражение LogQL.
	expression := "{" + s.config.ProjectLabel + "=" + strconv.Quote(project) + "}"
	return s.source.QueryRange(ctx, expression, request.Start, request.End, request.Limit)
}

// RecordSource читает записи по указанному пути; сервису не нужно знать формат файла.
type RecordSource interface {
	Read(context.Context, string) ([]model.LogRecord, error)
}

// OrderAnalyzer принимает готовые записи и возвращает результат; сам сервис их не классифицирует.
type OrderAnalyzer interface {
	Analyze(context.Context, []model.LogRecord) (model.AnalysisResult, error)
}

// AnalysisService соединяет чтение записей и их обработку в один сценарий.
type AnalysisService struct {
	source   RecordSource
	analyzer OrderAnalyzer
}

// NewAnalysisService получает оба компонента снаружи, поэтому их можно проверять независимо.
func NewAnalysisService(source RecordSource, analyzer OrderAnalyzer) *AnalysisService {
	return &AnalysisService{source: source, analyzer: analyzer}
}

// AnalyzeFile сначала читает файл, затем передает записи анализатору.
func (s *AnalysisService) AnalyzeFile(ctx context.Context, path string) (model.AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return model.AnalysisResult{}, err
	}
	records, err := s.source.Read(ctx, path)
	if err != nil {
		return model.AnalysisResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.AnalysisResult{}, err
	}
	// Источник уже вернул единый формат записей: анализатору не нужен исходный формат файла.
	result, err := s.analyzer.Analyze(ctx, records)
	if err != nil {
		return model.AnalysisResult{}, err
	}
	// Учебные записи считаем по явной метке источника, включая пропущенные анализатором.
	// Так CLI сможет отличить демонстрационный отчет от отчета по обычной выгрузке.
	result.SyntheticRecords = 0
	for _, record := range records {
		if record.Labels["dataset"] == "synthetic-example" {
			result.SyntheticRecords++
		}
	}
	return result, nil
}
