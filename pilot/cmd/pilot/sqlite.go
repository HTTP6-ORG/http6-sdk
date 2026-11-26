package main

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
static int bind_text(sqlite3_stmt *s, int i, const char *v) {
    return sqlite3_bind_text(s, i, v, -1, SQLITE_TRANSIENT);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type database struct{ db *C.sqlite3 }

func openDB(path string) (*database, error) {
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	d := &database{}
	if C.sqlite3_open(name, &d.db) != C.SQLITE_OK {
		return nil, d.err()
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, e := d.query(q); e != nil {
			return nil, e
		}
	}
	return d, nil
}
func openReadOnlyDB(path string) (*database, error) {
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	d := &database{}
	if C.sqlite3_open_v2(name, &d.db, C.SQLITE_OPEN_READONLY, nil) != C.SQLITE_OK {
		return nil, d.err()
	}
	return d, nil
}
func (d *database) err() error { return fmt.Errorf("SQLite: %s", C.GoString(C.sqlite3_errmsg(d.db))) }
func (d *database) close()     { C.sqlite3_close(d.db) }
func (d *database) query(query string, args ...string) ([]M, error) {
	sql := C.CString(query)
	defer C.free(unsafe.Pointer(sql))
	var stmt *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(d.db, sql, -1, &stmt, nil) != C.SQLITE_OK {
		return nil, d.err()
	}
	defer C.sqlite3_finalize(stmt)
	for i, arg := range args {
		if containsNUL(arg) {
			return nil, fmt.Errorf("NUL in database input")
		}
		v := C.CString(arg)
		rc := C.bind_text(stmt, C.int(i+1), v)
		C.free(unsafe.Pointer(v))
		if rc != C.SQLITE_OK {
			return nil, d.err()
		}
	}
	rows := []M{}
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			return rows, nil
		}
		if rc != C.SQLITE_ROW {
			return nil, d.err()
		}
		row := M{}
		for i := C.int(0); i < C.sqlite3_column_count(stmt); i++ {
			row[C.GoString(C.sqlite3_column_name(stmt, i))] = C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(stmt, i))))
		}
		rows = append(rows, row)
	}
}
func (d *database) exec(query string, args ...string) error {
	_, e := d.query(query, args...)
	return e
}
func (d *database) transaction(fn func() error) error {
	if e := d.exec("BEGIN IMMEDIATE"); e != nil {
		return e
	}
	defer d.exec("ROLLBACK")
	if e := fn(); e != nil {
		return e
	}
	return d.exec("COMMIT")
}
