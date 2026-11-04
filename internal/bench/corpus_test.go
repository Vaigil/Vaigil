// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aeroprove/aeroprove/internal/analyst"
)

// marshalCorpus renders a corpus the way corpus.json is written on disk:
// indented, HTML unescaped so a person diffing the file reads the words the
// catalogue wrote, and one field per line in declaration order — struct
// fields for shape, sorted keys where a map ever appears. Two runs of the
// generator produce the same bytes, which is what makes the test below a
// byte-for-byte one rather than a fuzzy one.
func marshalCorpus(c *Corpus) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// The corpus is generated, never hand-edited.
//
// corpus.json is the output of Generate, and this test is the lock: if the
// file and the generator disagree by one byte, the build fails and names the
// corpus as the thing to regenerate. Without it, a hand edit to the shipped
// data — a label nudged, a case's numbers "fixed" — would travel under a
// digest that still claimed to describe the generator's output, and every
// results document after it would cite a corpus that never existed as code.
func TestTheCorpusMatchesItsGenerator(t *testing.T) {
	shipped, err := corpusFS.ReadFile("corpus.json")
	if err != nil {
		t.Fatalf("the embedded corpus cannot be read: %v", err)
	}
	c := Generate()
	if err := c.Validate(); err != nil {
		t.Fatalf("the generator produced a corpus that refuses to validate, "+
			"which is a bug in the catalogue, not in Validate: %v", err)
	}
	fresh, err := marshalCorpus(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh, shipped) {
		t.Errorf("corpus.json is not what Generate writes. The corpus is " +
			"generated data: change it by changing generate.go and " +
			"regenerating, never by editing the file, or its digest stops " +
			"describing any code anybody can read")
	}
	// And the digest function, which a results document cites, is the digest
	// of exactly those bytes.
	sum := sha256.Sum256(shipped)
	if got := hex.EncodeToString(sum[:]); got != CorpusDigest() {
		t.Errorf("CorpusDigest() is %s and the sha256 of the embedded bytes "+
			"is %s; a document citing the digest would name a corpus it "+
			"did not run", CorpusDigest(), got)
	}
}

// The shipped corpus has to load through the same door a program does, with
// the schema check and the unknown-field refusal in the path: generating
// bytes and shipping bytes are two acts, and the second is where an
// accidental paste of the wrong file would otherwise land.
func TestTheCorpusThatShipsLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("the shipped corpus does not load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the shipped corpus does not validate: %v", err)
	}
	if c.Name != corpusName {
		t.Errorf("the corpus is named %q, not %q", c.Name, corpusName)
	}

	// Labels are a closed set, said twice: Validate refuses an open word,
	// and this says the set it is closed to is the three verdicts the
	// analyst asks — so a fourth word added to analyst without a corpus
	// schema bump is caught here rather than measured there.
	closed := map[string]bool{analyst.Real: true,
		analyst.FalsePositive: true, analyst.Benign: true}
	byClass := map[string]int{}
	for _, cs := range c.Cases {
		if !closed[cs.Expect] {
			t.Errorf("%s expects %q, which is not one of the three verdicts",
				cs.Name, cs.Expect)
		}
		if cs.Provenance != FromDispositions && cs.Provenance != HandLabelled {
			t.Errorf("%s carries provenance %q", cs.Name, cs.Provenance)
		}
		byClass[cs.Expect]++
	}

	// The counts the head of a results document reports, checked against a
	// second counting rather than against constants: the constants live in
	// the tests below this one, where their job is to notice a corpus that
	// changed shape out from under the metrics.
	s := c.Summary()
	if s.Cases != len(c.Cases) {
		t.Errorf("Summary counts %d cases over %d", s.Cases, len(c.Cases))
	}
	for class, n := range byClass {
		switch class {
		case analyst.Real:
			if s.Real != n {
				t.Errorf("Summary says %d real, counted %d", s.Real, n)
			}
		case analyst.FalsePositive:
			if s.False != n {
				t.Errorf("Summary says %d false-positive, counted %d",
					s.False, n)
			}
		case analyst.Benign:
			if s.Benign != n {
				t.Errorf("Summary says %d benign, counted %d", s.Benign, n)
			}
		}
	}
}

// The corpus's own shape, in numbers, so a change to the catalogue is a
// decision somebody sees: these say what the shipped set is, and the class
// balance and injection subset are the two things the metrics depend on.
//
// The one structural claim worth failing on: the injection subset covers
// every class. A subset drawn from one class would report a hijack rate
// about one kind of case, and nothing downstream would notice.
func TestTheCorpusShape(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	s := c.Summary()
	if s.Cases != 48 {
		t.Errorf("the corpus holds %d cases, not 48; if it grew on purpose, "+
			"update the shape this test pins", s.Cases)
	}
	if s.Real != 20 || s.False != 14 || s.Benign != 14 {
		t.Errorf("class balance is real=%d false=%d benign=%d, not 20/14/14",
			s.Real, s.False, s.Benign)
	}
	if s.Derived != 24 || s.Hand != 24 {
		t.Errorf("label provenance is derived=%d hand=%d, not 24/24",
			s.Derived, s.Hand)
	}
	if s.Inject == 0 || s.Inject > s.Cases/2 {
		t.Errorf("%d injected cases: none would measure nothing and more "+
			"than half the corpus would make the hijack run the expensive "+
			"half of every measurement", s.Inject)
	}
	injected := map[string]int{}
	for _, cs := range c.Cases {
		if cs.Inject {
			injected[cs.Expect]++
		}
	}
	for _, class := range []string{analyst.Real, analyst.FalsePositive,
		analyst.Benign} {
		if injected[class] == 0 {
			t.Errorf("no %s case is in the injection subset; a hijack rate "+
				"over one class of case is a number about that class, and "+
				"the document would present it as a general one", class)
		}
	}
}
