package db

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var (
	migrations = []migration{
		migration{
			ID: "add-session-tabel",
			Migrate: func(db *gorm.DB) error {
				return db.Exec(`
				CREATE TABLE sessions (
					id varchar(100) PRIMARY KEY,
					data blob NOT NULL,
					created_at timestamp NOT NULL default NOW(),
					updated_at timestamp NOT NULL default NOW()
				)`).Error
			},
			Rollback: func(db *gorm.DB) error {
				return db.DropTable("sessions").Error
			},
		},
	}
)

type migration struct {
	ID       string
	Migrate  func(*gorm.DB) error
	Rollback func(*gorm.DB) error
}

func ManualMigrateDatabase() error {
	db, err := GetConnection()
	if err != nil {
		return err
	}

	lastMigration, err := getLastMigration(db)
	if err != nil {
		return err
	}

	found := false

	runMigrations := func() error {
		for _, migration := range migrations {
			if migration.ID == lastMigration {
				found = true
				continue
			}

			if found {
				err = migration.Migrate(db)
				if err != nil {
					return err
				}

				_, err = db.DB().Exec("UPDATE migrations SET last_migration = ? WHERE id = 1", migration.ID)
				if err != nil {
					return err
				}
			}
		}

		return nil
	}

	//Run it the first time
	err = runMigrations()
	if err != nil {
		return err
	}

	//If the last migration isn't found set found to true and rerun so all migrations will execute
	if !found {
		found = true
		err = runMigrations()
		if err != nil {
			return err
		}
	}

	return nil
}

func getLastMigration(db *gorm.DB) (string, error) {
	if !db.HasTable("migrations") {
		err := db.Exec(`
		CREATE TABLE migrations (
			id INT PRIMARY KEY,
			last_migration VARCHAR(255) NOT NULL
		)`).Error

		if err != nil {
			return "", err
		}
	}

	rawDb := db.DB()

	rows, err := rawDb.Query("SELECT last_migration FROM migrations WHERE id = 1")
	if err != nil {
		return "", err
	}

	if !rows.Next() {
		err = rows.Close()
		if err != nil {
			return "", err
		}

		_, err := rawDb.Exec("INSERT INTO migrations(id, last_migration) VALUES (1, 'none')")
		if err != nil {
			return "", err
		}

		rows, err = rawDb.Query("SELECT last_migration FROM migrations WHERE id = 1")
		if err != nil {
			return "", err
		}

		if !rows.Next() {
			return "", errors.New("Can't create migration record")
		}
	}

	var lastMigration string
	err = rows.Scan(&lastMigration)
	if err != nil {
		return "", err
	}

	return lastMigration, nil
}
