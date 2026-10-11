package loki

import (
	"errors"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Query описывает сбор логов одного проекта за [Start, End) с необязательными фильтрами.
type Query struct {
	Project                     string
	Start, End                  time.Time
	Contains, Regex, LevelRegex string
}

// Config содержит только настройки клиента Loki; загружать окружение должен вызывающий код.
type Config struct {
	// URL может включать путь Grafana proxy; AllowHTTP нужен для явно разрешенного HTTP.
	URL          string
	ProjectLabel string
	Token        string
	OrgID        string
	AllowHTTP    bool
	Timeout      time.Duration

	// Лимиты ограничивают память и количество запросов при дочитывании большого периода.
	PageSize         int
	MaxRecords       int
	MaxRequests      int
	MaxResponseBytes int64
	MaxTotalBytes    int64
	MaxRange         time.Duration
}

// DefaultConfig задает конечные лимиты; URL и Token нужно указать перед вызовом New.
func DefaultConfig() Config {
	return Config{
		ProjectLabel:     "app",
		Timeout:          15 * time.Second,
		PageSize:         1000,
		MaxRecords:       100000,
		MaxRequests:      1000,
		MaxResponseBytes: 10 << 20,
		MaxTotalBytes:    64 << 20,
		MaxRange:         24 * time.Hour,
	}
}

// Имя метки попадает в URL и LogQL, поэтому допускается только фиксированный набор символов.
var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// validate проверяет настройки целиком до создания клиента и возвращает разобранный адрес.
func (config Config) validate() (*url.URL, error) {
	endpoint, err := validateEndpoint(config.URL, config.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if !labelName.MatchString(config.ProjectLabel) {
		return nil, errors.New("invalid project label name")
	}
	if err := config.validateLimits(); err != nil {
		return nil, err
	}
	if err := config.validateCredentials(); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// validateEndpoint требует базовый адрес без учетных данных, query-параметров и фрагмента.
func validateEndpoint(address string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil || u == nil || u.Hostname() == "" || u.Opaque != "" {
		return nil, errors.New("Loki URL must be an absolute base URL without credentials, query or fragment")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("Loki URL must be an absolute base URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowHTTP) {
		return nil, errors.New("Loki requires HTTPS; HTTP must be explicitly enabled")
	}
	if port := u.Port(); port != "" {
		if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
			return nil, errors.New("invalid Loki URL port")
		}
	}
	return u, nil
}

// validateLimits запрещает нулевые лимиты и переполнение при чтении дополнительного байта.
func (config Config) validateLimits() error {
	const message = "Loki timeouts and resource limits must be positive and finite"
	if config.Timeout <= 0 || config.MaxRange <= 0 {
		return errors.New(message)
	}
	if config.PageSize <= 0 || config.MaxRecords <= 0 || config.MaxRequests <= 0 {
		return errors.New(message)
	}
	for _, limit := range []int64{config.MaxResponseBytes, config.MaxTotalBytes} {
		if limit <= 0 || limit == math.MaxInt64 {
			return errors.New(message)
		}
	}
	return nil
}

// validateCredentials проверяет значения для HTTP-заголовков, не выводя сами секреты.
func (config Config) validateCredentials() error {
	invalidTokenCharacter := func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}
	if config.Token == "" || strings.ContainsFunc(config.Token, invalidTokenCharacter) {
		return errors.New("Grafana bearer token is required and must not contain whitespace or control characters")
	}
	if config.OrgID != "" {
		org, err := strconv.ParseUint(config.OrgID, 10, 64)
		if err != nil || org == 0 || strconv.FormatUint(org, 10) != config.OrgID {
			return errors.New("Grafana organization ID must be a positive integer")
		}
	}
	return nil
}
