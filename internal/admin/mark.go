// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

// The mark.
//
// # What it is
//
// A V whose two arms stop short of a node at its point, with a spark in its
// opening. The arms are events arriving from every source, the node is the
// one place they are brought together and judged, and the spark is the
// model that takes the first look. The first arm and the spark are drawn in
// one colour, the second arm and the node in the other, so the two halves
// read as two.
//
// # Why two paths, and why nonzero
//
// Each colour is one path, so each can be filled on its own. No shape in a
// path overlaps another, and within each every shape runs the same
// direction and fills with the nonzero rule, so nothing is cut out.
//
// # Why it is in Go rather than in the template
//
// Four surfaces draw it: the header on every screen, the sign-in page, the
// favicon and the installed application's icon. Four copies of a path string
// is four things to keep in step, and the one that falls behind is always the
// one nobody looks at. The template and the icon route both read this.
//
// Coordinates are absolute in a 24×24 box, so a consumer that only reads
// the `d` attribute — an icon pipeline, an SVG favicon — gets the same
// shape as the browser does.
const MarkPath = MarkFirst + " " + MarkSecond

// MarkFirst is the first arm and the spark, and MarkSecond the second arm
// and the node at the point.
const (
	MarkFirst  = "M2.47 4.19L7.97 16.19A1.90 1.90 0 0 0 11.43 14.61L5.93 2.61A1.90 1.90 0 0 0 2.47 4.19Z M12.00 3.80Q12.00 7.00 15.20 7.00Q12.00 7.00 12.00 10.20Q12.00 7.00 8.80 7.00Q12.00 7.00 12.00 3.80Z"
	MarkSecond = "M18.07 2.61L12.57 14.61A1.90 1.90 0 0 0 16.03 16.19L21.53 4.19A1.90 1.90 0 0 0 18.07 2.61Z M9.20 19.80A2.80 2.80 0 1 0 14.80 19.80A2.80 2.80 0 1 0 9.20 19.80Z"
)

// The mark's colours, for the files that cannot take them from a
// stylesheet: the favicon and the installed application's icon. The
// stylesheet has the same pair, with lighter tones for the dark theme.
const (
	MarkFirstColour  = "#0b57d0"
	MarkSecondColour = "#7b4dff"
)

// MarkSVG is the mark as a standalone document, for the favicon and the
// installed icon.
//
// currentColor is deliberately NOT used here. A file fetched as an icon has no
// inherited colour to take, so it needs a literal one — and the brand's, when
// the operator set a valid one, so an installed window and a browser tab carry
// the same accent as the interface they belong to.
func MarkSVG(colour string) string {
	if colour == "" {
		colour = MarkFirstColour
	}
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
		`<path fill="` + colour + `" d="` + MarkFirst + `"/>` +
		`<path fill="` + MarkSecondColour + `" d="` + MarkSecond + `"/></svg>`
}
