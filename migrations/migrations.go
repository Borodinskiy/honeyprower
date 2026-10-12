package migrations

import _ "embed"

//go:embed 001_schema.sql
var SchemaSQL string

//go:embed 002_seed.sql
var SeedSQL string
