// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strconv"
	"strings"
	"testing"
)

// The canonical M3 token layer, held to the roles it names.
//
// style.css carries an alias block — --md-sys-color-primary: var(--primary),
// and one per role — so a component can be written in the names the Material
// specifications publish while the roles underneath stay what the contrast
// test checks. An alias layer nobody tests is a second place for a colour to
// drift: the role is corrected, the alias still names the old value, and the
// component that reads the canonical name quietly disagrees with every other
// component on the screen. So each alias is resolved in both schemes and
// compared with the role it names, and the same table holds the component
// tokens that name a colour role.
var aliasRoles = [][2]string{
	{"--md-sys-color-primary", "--primary"},
	{"--md-sys-color-on-primary", "--on-primary"},
	{"--md-sys-color-primary-container", "--primary-container"},
	{"--md-sys-color-on-primary-container", "--on-primary-container"},
	{"--md-sys-color-secondary", "--secondary"},
	{"--md-sys-color-on-secondary", "--on-secondary"},
	{"--md-sys-color-secondary-container", "--secondary-container"},
	{"--md-sys-color-on-secondary-container", "--on-secondary-container"},
	{"--md-sys-color-tertiary", "--tertiary"},
	{"--md-sys-color-on-tertiary", "--on-tertiary"},
	{"--md-sys-color-tertiary-container", "--tertiary-container"},
	{"--md-sys-color-on-tertiary-container", "--on-tertiary-container"},
	{"--md-sys-color-error", "--error"},
	{"--md-sys-color-on-error", "--on-error"},
	{"--md-sys-color-error-container", "--error-container"},
	{"--md-sys-color-on-error-container", "--on-error-container"},
	{"--md-sys-color-surface", "--surface"},
	{"--md-sys-color-on-surface", "--on-surface"},
	{"--md-sys-color-surface-variant", "--surface-variant"},
	{"--md-sys-color-on-surface-variant", "--on-surface-variant"},
	{"--md-sys-color-surface-container-lowest", "--surface-container-lowest"},
	{"--md-sys-color-surface-container-low", "--surface-container-low"},
	{"--md-sys-color-surface-container", "--surface-container"},
	{"--md-sys-color-surface-container-high", "--surface-container-high"},
	{"--md-sys-color-surface-container-highest", "--surface-container-highest"},
	{"--md-sys-color-surface-dim", "--surface-dim"},
	{"--md-sys-color-surface-bright", "--surface-bright"},
	{"--md-sys-color-surface-tint", "--primary"},
	{"--md-sys-color-outline", "--outline"},
	{"--md-sys-color-outline-variant", "--outline-variant"},
	{"--md-sys-color-inverse-surface", "--inverse-surface"},
	{"--md-sys-color-inverse-on-surface", "--inverse-on-surface"},
	{"--md-sys-color-inverse-primary", "--inverse-primary"},
	{"--md-sys-color-shadow", "--shadow"},
	{"--md-sys-color-scrim", "--scrim"},
	{"--md-sys-color-primary-fixed", "--primary-fixed"},
	{"--md-sys-color-primary-fixed-dim", "--primary-fixed-dim"},
	{"--md-sys-color-on-primary-fixed", "--on-primary-fixed"},
	{"--md-sys-color-on-primary-fixed-variant", "--on-primary-fixed-variant"},
	{"--md-sys-color-secondary-fixed", "--secondary-fixed"},
	{"--md-sys-color-secondary-fixed-dim", "--secondary-fixed-dim"},
	{"--md-sys-color-on-secondary-fixed", "--on-secondary-fixed"},
	{"--md-sys-color-on-secondary-fixed-variant", "--on-secondary-fixed-variant"},
	{"--md-sys-color-tertiary-fixed", "--tertiary-fixed"},
	{"--md-sys-color-tertiary-fixed-dim", "--tertiary-fixed-dim"},
	{"--md-sys-color-on-tertiary-fixed", "--on-tertiary-fixed"},
	{"--md-sys-color-on-tertiary-fixed-variant", "--on-tertiary-fixed-variant"},
	// The component tokens that name a colour role, held the same way: the
	// snackbar's inverse trio, the dialog and search-view containers, the
	// selected chips and the badge.
	{"--md-comp-snackbar-container-color", "--inverse-surface"},
	{"--md-comp-snackbar-supporting-text-color", "--inverse-on-surface"},
	{"--md-comp-snackbar-action-label-color", "--inverse-primary"},
	{"--md-comp-dialog-container-color", "--surface-container-high"},
	{"--md-comp-search-view-container-color", "--surface-container-high"},
	{"--md-comp-filter-chip-selected-container-color", "--secondary-container"},
	{"--md-comp-filter-chip-selected-label-text-color", "--on-secondary-container"},
	{"--md-comp-outlined-segmented-button-selected-container-color", "--secondary-container"},
	{"--md-comp-outlined-segmented-button-selected-label-text-color", "--on-secondary-container"},
	{"--md-comp-badge-color", "--error"},
	{"--md-comp-badge-label-text-color", "--on-error"},
}

func TestTheCanonicalAliasesMatchTheRolesTheyName(t *testing.T) {
	if len(aliasRoles) < 40 {
		t.Fatalf("%d aliases; the layer has stopped being written and this "+
			"test has stopped checking it", len(aliasRoles))
	}
	for _, scheme := range []string{"light", "dark"} {
		tok := tokens(t, scheme)
		for _, pair := range aliasRoles {
			alias, role := pair[0], pair[1]
			a, ok := tok[alias]
			if !ok || a == "" {
				t.Errorf("%s: %s is not defined in the %s scheme",
					scheme, alias, scheme)
				continue
			}
			if a != tok[role] {
				t.Errorf("%s: %s resolves to %s, but the role it names "+
					"(%s) resolves to %s. An alias that disagrees with its "+
					"role is a component reading a colour nobody chose",
					scheme, alias, a, role, tok[role])
			}
		}
	}
}

// The state layers are the specification's own numbers — hover 8, focus 12,
// pressed 12, dragged 16 — and they had drifted once already (focus and
// press were 10), which is invisible: a state layer at the wrong opacity is
// still a state layer, only a hover nobody can quite see. Named here so the
// four numbers cannot move without a test saying they did.
func TestStateLayersAreTheSpecifiedPercentages(t *testing.T) {
	want := map[string]string{
		"--state-hover": "8%",
		"--state-focus": "12%",
		"--state-press": "12%",
		"--state-drag":  "16%",
		"--md-sys-state-hover-state-layer-opacity":   "8%",
		"--md-sys-state-focus-state-layer-opacity":   "12%",
		"--md-sys-state-pressed-state-layer-opacity": "12%",
		"--md-sys-state-dragged-state-layer-opacity": "16%",
	}
	tok := tokens(t, "light")
	for name, w := range want {
		if got := tok[name]; got != w {
			t.Errorf("%s is %q, not %q; the M3 state layers are 8/12/12/16 "+
				"and everything that hovers inherits this", name, got, w)
		}
	}
}

// Material's focus indicator is the secondary colour, across every component
// — not primary, so the ring still reads against a primary-filled control.
// The ring was primary in four places before it was one token; holding the
// token to secondary is what keeps those four from growing back.
func TestTheFocusRingIsTheSecondaryColour(t *testing.T) {
	for _, scheme := range []string{"light", "dark"} {
		tok := tokens(t, scheme)
		if tok["--focus-ring"] != tok["--secondary"] {
			t.Errorf("%s: the focus ring is %s, not the secondary colour %s; "+
				"the M3 focus spec draws the ring in secondary so it "+
				"contrasts with primary-filled controls too",
				scheme, tok["--focus-ring"], tok["--secondary"])
		}
	}
}

// The six Expressive springs, verified by what makes each one itself.
//
// The curves in the stylesheet are samples, not parameters — CSS has no
// damping or stiffness — but the parameters leave fingerprints a test can
// read: a unit spring's overshoot is set by its damping ratio alone (about
// 9% at 0.6, about 1.5% at 0.8, none at all once the ratio reaches 1), and
// each curve's duration token is the settle time the stiffness implies. So
// the six damping/stiffness pairs of androidx's ExpressiveMotionTokens —
// spatial 0.6/800, 0.8/380, 0.8/200; effects 1.0 with 3800, 1600, 800 —
// are checked as: fast spatial overshoots, default and slow spatial settle
// from just above 1, the three effect curves never pass 1, and the six
// durations are the settle times those stiffnesses produce (360, 430, 600,
// 150, 230, 330 ms). A curve redrawn to "look springy" fails one of these.
func TestTheSixExpressiveSpringsAreTheSpecification(t *testing.T) {
	css := string(mustAsset(t, "style.css"))

	durations := map[string]string{
		"--motion-fast-spatial-duration":    "360ms",
		"--motion-default-spatial-duration": "430ms",
		"--motion-slow-spatial-duration":    "600ms",
		"--motion-fast-effects-duration":    "150ms",
		"--motion-default-effects-duration": "230ms",
		"--motion-slow-effects-duration":    "330ms",
	}
	// What the damping ratio of each curve means for its peak. Spatial
	// springs overshoot; effect springs (damping 1.0) must not, because "a
	// colour that overshoots lands on a hue nobody chose".
	peaks := map[string]struct{ min, max float64 }{
		"--motion-fast-spatial":    {1.05, 1.25},  // damping 0.6: ~9% over
		"--motion-default-spatial": {1.001, 1.05}, // damping 0.8: ~1.5% over
		"--motion-slow-spatial":    {1.001, 1.05}, // damping 0.8: ~1.5% over
		"--motion-fast-effects":    {0.99, 1.0001},
		"--motion-default-effects": {0.99, 1.0001},
		"--motion-slow-effects":    {0.99, 1.0001},
	}

	// The first declaration of each token, not the last: the durations are
	// re-declared as 0ms inside the prefers-reduced-motion block further down
	// the file, which is the kill switch working, not the design value.
	decls := map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(css, -1) {
		if _, ok := decls[m[1]]; !ok {
			decls[m[1]] = strings.TrimSpace(m[2])
		}
	}
	for name, wantDur := range durations {
		d, ok := decls[name]
		if !ok || !strings.HasPrefix(d, wantDur) {
			t.Errorf("%s is %q, not %s — the settle time the spring's "+
				"stiffness implies", name, d, wantDur)
		}
	}
	for name, band := range peaks {
		v, ok := decls[name]
		if !ok || !strings.HasPrefix(v, "linear(") {
			t.Errorf("%s is %q, not a sampled curve", name, v)
			continue
		}
		samples := []float64{}
		for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(v, "linear("), ")"), ",") {
			f, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
			if err != nil {
				continue // a percentage keyword, if one is ever added
			}
			samples = append(samples, f)
		}
		if len(samples) < 20 {
			t.Errorf("%s has %d samples; it is no longer the forty-point "+
				"curve the comment says it is", name, len(samples))
			continue
		}
		if first, last := samples[0], samples[len(samples)-1]; first != 0 || last != 1 {
			t.Errorf("%s runs %v to %v; a spring starts at rest where it was "+
				"and ends at rest where it was asked to be", name, first, last)
		}
		peak := samples[0]
		for _, s := range samples {
			if s > peak {
				peak = s
			}
		}
		if peak < band.min || peak > band.max {
			t.Errorf("%s peaks at %v; the band [%v, %v] is what its damping "+
				"ratio produces, so the curve is not the spring it is named",
				name, peak, band.min, band.max)
		}
	}
}
