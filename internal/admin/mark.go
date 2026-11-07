// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

// The mark.
//
// # What it is
//
// A capital A whose crossbar is a streamline: it comes out from behind the
// left leg, passes over the right one, and leaves rising, cut at an angle.
// Air through the tunnel, and lift out of it. The legs are drawn in one
// colour and the streamline in the other, and where they cross there is a
// gap, so at the size of a browser tab the weave still reads.
//
// # Why two paths, and why nonzero
//
// Each colour is one path, so each can be filled on its own: the first is
// the A — the left leg, the apex and the right leg down to the gap, then the
// right foot below it — and the second is the streamline. Neither uses a
// mask, a stroke or a gradient, so a consumer that only reads the `d`
// attribute — an icon pipeline, an SVG favicon — draws what the browser
// draws. Within each path the shapes do not overlap and fill nonzero.
//
// The paths are computed from the construction in docs/brand, scaled from
// its 64-unit box to this 24-unit one, rather than traced, so the two never
// drift apart.
//
// # Why it is in Go rather than in the template
//
// Four surfaces draw it: the header on every screen, the sign-in page, the
// favicon and the installed application's icon. Four copies of a path string
// is four things to keep in step, and the one that falls behind is always the
// one nobody looks at. The template and the icon route both read this.
const MarkPath = MarkFirst + " " + MarkSecond

// MarkFirst is the A, and MarkSecond the streamline.
const (
	MarkFirst  = "M6.42 22.04L6.05 22.59L5.50 22.94L4.85 23.06L4.21 22.92L3.66 22.55L3.31 22.00L3.19 21.35L3.33 20.71L3.33 20.71L12.00 0.62L17.14 12.53L17.06 12.60L16.87 12.76L16.68 12.91L16.48 13.05L16.31 13.17L15.81 13.43L15.30 13.69L14.76 13.93L14.22 14.16L14.18 14.17L12.00 9.13L6.42 22.04Z M18.85 16.49L20.67 20.71L20.81 21.35L20.69 22.00L20.34 22.55L19.79 22.92L19.15 23.06L18.50 22.94L17.95 22.59L17.58 22.04L15.75 17.82L16.24 17.65L16.90 17.40L17.55 17.12L18.19 16.83L18.58 16.64Z"
	MarkSecond = "M8.90 18.39L9.25 18.36L9.93 18.29L10.61 18.20L11.30 18.09L11.97 17.97L12.65 17.83L13.32 17.67L13.99 17.50L14.64 17.31L15.30 17.11L15.94 16.88L16.57 16.64L17.20 16.38L17.81 16.10L18.16 15.93L18.48 15.75L18.80 15.56L19.11 15.36L19.41 15.15L19.71 14.93L20.00 14.69L20.28 14.45L20.56 14.19L20.83 13.92L21.09 13.65L21.34 13.36L21.59 13.07L21.83 12.77L22.06 12.46L22.29 12.14L22.51 11.81L22.71 11.49L23.86 9.49L20.04 9.96L19.89 10.26L19.74 10.53L19.58 10.80L19.42 11.07L19.26 11.32L19.09 11.57L18.91 11.81L18.73 12.04L18.54 12.27L18.36 12.48L18.16 12.69L17.96 12.89L17.76 13.08L17.55 13.27L17.34 13.44L17.12 13.61L16.90 13.76L16.69 13.90L16.16 14.18L15.62 14.44L15.07 14.70L14.50 14.93L13.92 15.16L13.33 15.37L12.73 15.56L12.13 15.74L11.51 15.91L10.89 16.07L10.26 16.21L9.80 16.31Z"
)

// The mark's colours, for the files that cannot take them from a
// stylesheet: the favicon and the installed application's icon. The
// stylesheet has the same pair, with lighter tones for the dark theme.
const (
	MarkFirstColour  = "#0A1F44"
	MarkSecondColour = "#0096B4"
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
