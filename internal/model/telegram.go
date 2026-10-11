package model

// BotInfo содержит сведения о боте, полученные через Telegram getMe.
type BotInfo struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// TelegramChat — адресат, замеченный при локальном чтении обновлений.
// Наличие в списке не выдает доступ и не подписывает чат на уведомления.
type TelegramChat struct {
	ID     int64
	Title  string
	Type   string
	UserID int64
}

// TelegramUpdate сохраняет ID даже для события без текста: его тоже нужно подтвердить.
type TelegramUpdate struct {
	ID       int64                  `json:"update_id"`
	Message  *TelegramMessage       `json:"message"`
	Callback *TelegramCallbackQuery `json:"callback_query"`
}

// TelegramCallbackQuery — нажатие кнопки под сообщением; доступ проверяет обработчик.
type TelegramCallbackQuery struct {
	ID      string           `json:"id"`
	Data    string           `json:"data"`
	Message *TelegramMessage `json:"message"`
	From    struct {
		ID    int64 `json:"id"`
		IsBot bool  `json:"is_bot"`
	} `json:"from"`
}

// TelegramMessage содержит только поля, необходимые для обработки команды из чата.
type TelegramMessage struct {
	ID   int64  `json:"message_id"`
	Date int64  `json:"date"`
	Text string `json:"text"`
	Chat struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	From struct {
		ID    int64 `json:"id"`
		IsBot bool  `json:"is_bot"`
	} `json:"from"`
}
