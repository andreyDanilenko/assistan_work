// Пакет utils содержит общие технические функции без логики заказов.
package utils

import (
	"net/http"
	"time"
)

// NewHTTPClient задает тайм-аут и оставляет стандартную проверку TLS-сертификата.
// Редиректы запрещены, чтобы запрос с токеном не ушел на адрес из ответа сервера.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
