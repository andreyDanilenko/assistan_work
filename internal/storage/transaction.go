package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
)

// SQLite оставляет транзакцию открытой при SQLITE_BUSY на COMMIT, хотя sql.Tx
// уже завершён. Держим соединение у себя до явного ROLLBACK этой транзакции.
type writeTransaction struct {
	*sql.Tx
	conn *sql.Conn
}

func beginWrite(ctx context.Context, db *sql.DB) (*writeTransaction, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &writeTransaction{Tx: tx, conn: conn}, nil
}

func (tx *writeTransaction) Commit() error {
	defer tx.conn.Close()
	err := tx.Tx.Commit()
	if err != nil {
		// Контекст исходного запроса может быть уже отменён; откат всё равно обязателен.
		if _, rollbackErr := tx.conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
			// Непроверенное соединение не должно вернуться в пул с незавершённой записью.
			_ = tx.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}
	return err
}

func (tx *writeTransaction) Rollback() error {
	defer tx.conn.Close()
	return tx.Tx.Rollback()
}
