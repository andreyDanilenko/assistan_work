// Пакет cli связывает команды пользователя со сценариями приложения и выводом в терминал.
package cli

import (
	"context"
	"fmt"
	"io"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/report"
)

// Executor — нужная CLI операция сервиса. Реальный сервис или его замену передает main.
type Executor interface {
	Execute(context.Context, app.Request) (model.Response, error)
}

// Run запускает команду через переданный сервис и возвращает код завершения процесса.
func Run(ctx context.Context, executor Executor, options Options, output, diagnostic io.Writer) int {
	// Ограничиваем длительность всей команды; родительская отмена также сохраняется.
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	response, err := executor.Execute(ctx, options.Request)
	if err != nil {
		WriteError(diagnostic, "Запрос не выполнен", err)
		printAccessHint(diagnostic, response.StatusCode)
		return 1
	}
	if err := printResponse(output, options, response); err != nil {
		fmt.Fprintln(diagnostic, "Не удалось вывести ответ.")
		return 1
	}
	// Ответ уже показан, но лимит страницы не позволяет считать период полным.
	// Код 2 отличает этот случай от успешной полной выборки и ошибки запроса.
	if response.Truncated {
		fmt.Fprintln(diagnostic, "Достигнут лимит страницы: в периоде могут быть другие записи. Эта команда делает один запрос.")
		return 2
	}
	return 0
}

// FileAnalyzer позволяет запускать анализ, не зная устройства чтения файла и правил заказов.
type FileAnalyzer interface {
	AnalyzeFile(context.Context, string) (model.AnalysisResult, error)
}

// RunAnalysis получает готовый сервис; CLI не создает клиентов и не читает настройки анализа.
func RunAnalysis(ctx context.Context, service FileAnalyzer, options Options, output, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	result, err := service.AnalyzeFile(ctx, options.File)
	if err != nil {
		WriteError(diagnostic, "Анализ не выполнен", err)
		return 1
	}
	if err := report.WriteFile(output, result, options.AllOrders); err != nil {
		fmt.Fprintln(diagnostic, "Не удалось вывести результат анализа.")
		return 1
	}
	return 0
}
