#pragma once

/// How a transaction that writes has to begin.  Internal to libsession: Core and Client both open
/// these against the one database.

#include <SQLiteCpp/Transaction.h>

#include <session/sqlite.hpp>

namespace session::core {

/// Begins a transaction that will write, taking the database's write lock at BEGIN.
///
/// The database is in WAL mode and is not ours alone: another process -- a notification extension,
/// say -- or another Core on the same file is another connection, committing whenever it likes.  A
/// deferred transaction reads from a snapshot and asks for the write lock only at its first write,
/// and if another connection has committed since that snapshot was taken, the write fails at once
/// with SQLITE_BUSY: no amount of waiting makes a stale snapshot current, so the busy timeout is
/// never consulted.  Taking the lock at BEGIN means the snapshot is taken with it, and contention
/// becomes the busy timeout's to wait out.
///
/// Every transaction that may write uses this, even one whose first statement is a write, so that
/// whether it is safe does not hang on statement order.  A transaction that only reads keeps the
/// default (deferred) behaviour: it needs no lock, and taking one would serialise readers behind
/// writers for nothing.
///
/// Holding the write lock blocks every other writer on the file, in this process and out of it, so
/// what runs inside one of these should be the writes and the reads that decide them.
inline SQLite::Transaction write_transaction(sqlite::Connection& c) {
    return SQLite::Transaction{c.sql, SQLite::TransactionBehavior::IMMEDIATE};
}

}  // namespace session::core
