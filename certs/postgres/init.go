// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import migrate "github.com/rubenv/sql-migrate"

func Migration() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "certs_1",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS certs (
						client_id      TEXT NOT NULL,
						expiry_time    TIMESTAMPTZ NOT NULL,
						serial_number  TEXT NOT NULL,
						revoked        BOOLEAN DEFAULT FALSE,
						PRIMARY KEY (client_id, serial_number)
					);`,
				},
				Down: []string{
					"DROP TABLE IF EXISTS certs;",
				},
			},
			{
				Id: "certs_2",
				Up: []string{
					`ALTER TABLE certs DROP CONSTRAINT IF EXISTS certs_pkey;`,
					`ALTER TABLE certs
						ALTER COLUMN serial_number TYPE VARCHAR(40) USING serial_number::VARCHAR(40),
						ALTER COLUMN serial_number SET NOT NULL;`,
					`ALTER TABLE certs
						ADD COLUMN IF NOT EXISTS certificate TEXT,
						ADD COLUMN IF NOT EXISTS "key" TEXT,
						ADD COLUMN IF NOT EXISTS entity_id VARCHAR(36),
						ADD COLUMN IF NOT EXISTS type TEXT;`,
					`ALTER TABLE certs
						ADD CONSTRAINT certs_type_chk
						CHECK (type IN ('RootCA', 'IntermediateCA', 'ClientCert'));`,
					`ALTER TABLE certs ADD CONSTRAINT certs_pkey PRIMARY KEY (serial_number);`,
				},
				Down: []string{
					`ALTER TABLE certs DROP CONSTRAINT IF EXISTS certs_pkey;`,
					`ALTER TABLE certs DROP CONSTRAINT IF EXISTS certs_type_chk;`,
					`ALTER TABLE certs DROP COLUMN IF EXISTS type;`,
					`ALTER TABLE certs DROP COLUMN IF EXISTS entity_id;`,
					`ALTER TABLE certs DROP COLUMN IF EXISTS "key";`,
					`ALTER TABLE certs DROP COLUMN IF EXISTS certificate;`,
					`ALTER TABLE certs
						ALTER COLUMN serial_number TYPE TEXT USING serial_number::TEXT;`,
					`ALTER TABLE certs ADD CONSTRAINT certs_pkey PRIMARY KEY (client_id, serial_number);`,
				},
			},
		},
	}
}
