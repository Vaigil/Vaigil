// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import ()

// The state every installation is in for its first few minutes.
//
// Every other test in this package starts from setup, and setup saves a draft
// before it hands the server over. That is a reasonable thing for a test about
// editing to do, and it meant that nothing here had ever opened a store with
// nothing in it — so the first save through the browser, on a machine somebody
// had just run init on, panicked on a nil map and dropped the connection with
// no response at all. Two more screens answered 500 with "not an object id: """,
// which reads to a new user as a broken installation.
//
// The empty store is not an edge case. It is the state the product is in when
// somebody sees it for the first time, and it is the one state no test covered.
