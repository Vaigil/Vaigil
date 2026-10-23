// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import ()

// Removing a page through the interface.
//
// The capability existed on the command line and not in the browser, and no
// test noticed for the same reason nobody did: every test here opens the
// screens that exist and checks they work. A screen that was never built has
// nothing to fail. See TestEveryCommandHasAnInterface in this package for the
// check that now asks the question the other way round.
