package auth

import (
	"strconv"
	"strings"
	"time"
)

// filter builds a WHERE clause by accumulating only the predicates that are
// actually in play, numbering placeholders as it goes.
//
// The obvious alternative — a fixed clause like `WHERE ($1 = ” OR email = $1)`
// with a neutral empty-string argument — reads well and is a trap: Postgres
// cannot use an index for a disjunction over a parameter, so every list query
// degrades to a sequential scan of the whole table. Building the predicate
// conditionally keeps the index in play.
type filter struct {
	clauses []string
	args    []any
}

// bind records an argument and returns its positional placeholder.
func (f *filter) bind(arg any) string {
	f.args = append(f.args, arg)
	return "$" + strconv.Itoa(len(f.args))
}

// eq adds `col = $N`, or nothing when the value is empty.
func (f *filter) eq(col, value string) {
	if value == "" {
		return
	}
	f.clauses = append(f.clauses, col+" = "+f.bind(value))
}

// notEq adds `col <> $N` unconditionally; used for constants, not user input.
func (f *filter) notEq(col, value string) {
	f.clauses = append(f.clauses, col+" <> "+f.bind(value))
}

// from and to add inclusive time bounds, or nothing when unset.
func (f *filter) from(col string, t time.Time) { f.timeBound(col, ">=", t) }
func (f *filter) to(col string, t time.Time)   { f.timeBound(col, "<=", t) }

func (f *filter) timeBound(col, op string, t time.Time) {
	if t.IsZero() {
		return
	}
	f.clauses = append(f.clauses, col+" "+op+" "+f.bind(t))
}

// keyset adds the "strictly older than the cursor" predicate as a row-value
// comparison, which is what makes (timestamp, id) a total order even when two
// rows share a timestamp.
func (f *filter) keyset(cols string, c Cursor, id any) {
	if c.IsZero() {
		return
	}
	f.clauses = append(f.clauses, "("+cols+") < ("+f.bind(c.Time)+", "+f.bind(id)+")")
}

func (f *filter) where() string {
	if len(f.clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(f.clauses, " AND ")
}

// page renders ORDER BY + LIMIT. The limit is interpolated rather than bound
// because it has already been clamped to [1, MaxPageSize] by Page.Normalize.
func orderAndLimit(cols string, limit int) string {
	return " ORDER BY " + cols + " LIMIT " + strconv.Itoa(limit)
}
