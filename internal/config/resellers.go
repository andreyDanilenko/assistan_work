package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// LoadResellers загружает справочник ID → название один раз при запуске.
// Справочник необязателен: без файла остаются исходные ID. Ошибочный JSON не используется частично.
func LoadResellers(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("не удалось открыть RESELLER_MAP_FILE")
	}
	defer file.Close()
	const maxBytes = 1 << 20
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, errors.New("справочник реселлеров должен быть обычным JSON-файлом до 1 МиБ")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(body) > maxBytes || !utf8.Valid(body) {
		return nil, errors.New("не удалось прочитать справочник реселлеров")
	}
	var names map[string]string
	if json.Unmarshal(body, &names) != nil || names == nil {
		return nil, errors.New("справочник реселлеров должен иметь формат {\"ID\":\"Название\"}")
	}
	identifier := regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	for id, name := range names {
		name = strings.TrimSpace(name)
		if !identifier.MatchString(id) || name == "" || utf8.RuneCountInString(name) > 200 || strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			return nil, errors.New("в справочнике реселлеров некорректный ID или название; названия должны быть непустыми, до 200 символов, без управляющих символов")
		}
		names[id] = name
	}
	return names, nil
}
