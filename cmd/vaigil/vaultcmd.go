// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/vaigil/internal/atomicfile"
	"github.com/quilzo/vaigil/internal/audit"
	"github.com/quilzo/vaigil/internal/vault"
)

// The keyring the credentials this store holds are sealed under: what a
// connector signs in with, and the secret a feed is checked against. The
// keyring file holds ids and metadata, never key material, which comes
// from outside the store (keySource).

func keyringPath(root string) string { return filepath.Join(root, "keyring.json") }

// keySource says where the key encryption key comes from.
//
// Never from the code, and by default not from the data directory — a key
// stored beside the thing it protects protects nothing against somebody who
// takes the directory. The command form is the interesting one: it makes an
// HSM, a cloud KMS, a password manager or a hardware token work without this
// program knowing any of them exist.
const (
	keyEnv     = "VAIGIL_KEY"
	keyCmdEnv  = "VAIGIL_KEY_COMMAND"
	keyFileEnv = "VAIGIL_KEY_FILE"
)

// loadKeyring reads the keyring and supplies key material from outside.
//
// Returns nil with no error when encryption is not configured. That is the
// default and it has to stay silent, because a store that encrypted itself with
// a key generated on first run is a store whose contents are lost the first
// time somebody reimages a machine.
func loadKeyring(root string) (*vault.Keyring, error) {
	raw, err := os.ReadFile(keyringPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kr := &vault.Keyring{}
	if err := json.Unmarshal(raw, kr); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", keyringPath(root), err)
	}

	material, err := keyMaterial()
	if err != nil {
		return nil, err
	}
	if len(material) == 0 {
		return nil, fmt.Errorf(
			"this store is encrypted but no key was supplied.\n"+
				"  Set one of:\n"+
				"    %s          the key itself, base64\n"+
				"    %s     a file holding it\n"+
				"    %s  a command that prints it — this is how a\n"+
				"                            KMS, an HSM or a password manager plugs in",
			keyEnv, keyFileEnv, keyCmdEnv)
	}

	// One supplied key, applied to whichever keyring entry it matches by id.
	// Multiple keys are supplied as id=base64 pairs, so a rotation in progress
	// can still read what the previous key wrapped.
	if err := applyMaterial(kr, material); err != nil {
		return nil, err
	}
	return kr, nil
}

func keyMaterial() (string, error) {
	if cmd := os.Getenv(keyCmdEnv); cmd != "" {
		// Run through the shell so an operator can write a real command with
		// arguments and a pipe. This is an operator-supplied command from the
		// environment of the process, not caller input — anybody who can set it
		// can already run anything as this user.
		out, err := exec.Command("/bin/sh", "-c", cmd).Output()
		if err != nil {
			return "", fmt.Errorf("%s failed: %w", keyCmdEnv, err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	if path := os.Getenv(keyFileEnv); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr,
				"%swarning: %s is mode %04o — the key is readable by other "+
					"local accounts%s\n",
				yellow, path, info.Mode().Perm(), reset)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(keyEnv)), nil
}

// applyMaterial attaches key bytes to the keyring entries.
func applyMaterial(kr *vault.Keyring, material string) error {
	assign := func(id, encoded string) error {
		k, err := vault.DecodeKey(encoded)
		if err != nil {
			return fmt.Errorf("key %q: %w", id, err)
		}
		entry, ok := kr.Keys[id]
		if !ok {
			return fmt.Errorf("key %q was supplied but the keyring does not "+
				"list it; the ids have to match or an object cannot say which "+
				"key wrapped it", id)
		}
		entry.Key = k
		return nil
	}

	for _, part := range strings.Split(material, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// A bare key is tried first, and this ordering is the whole of the
		// fix for a bug that unit tests could not see: base64 ends in `=`
		// padding, so splitting on `=` to find an `id=key` pair chopped a
		// perfectly good key at its own padding and read the front half as an
		// id. Deciding by whether the part *is* a key removes the ambiguity
		// instead of trying to parse around it.
		if _, err := vault.DecodeKey(part); err == nil {
			// A bare key is only unambiguous when there is one entry. After a
			// rotation there are at least two, and assuming the bare key is the
			// active one silently attached the *old* key's material to the
			// *new* key's id — which then failed at the first read with a
			// message about a key that had in fact been supplied. Refusing is
			// the only honest answer: the operator has to say which.
			if len(kr.Keys) > 1 {
				return fmt.Errorf(
					"this keyring holds %d keys (%s), so a bare key is "+
						"ambiguous — it could belong to any of them, and "+
						"guessing wrong looks like a corrupt store rather than "+
						"a mistyped variable.\n  Name them: %s=k1=…,k2=…",
					len(kr.Keys), strings.Join(kr.IDs(), ", "), keyEnv)
			}
			if err := assign(kr.Active, part); err != nil {
				return err
			}
			continue
		}
		if id, encoded, ok := strings.Cut(part, "="); ok {
			if err := assign(strings.TrimSpace(id), encoded); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("%q is neither a key nor an id=key pair", part)
	}

	if entry, ok := kr.Keys[kr.Active]; !ok || len(entry.Key) == 0 {
		return fmt.Errorf("no material was supplied for the active key %q",
			kr.Active)
	}
	return nil
}

func cmdVault(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return vaultStatus(root)
	case "enable":
		return vaultEnable(root, args[1:])
	case "rotate":
		return vaultRotate(root, args[1:])
	case "rewrap":
		return vaultRewrap(root, args[1:])
	default:
		return fmt.Errorf(
			"unknown vault command %q; try status, enable, rotate or rewrap",
			args[0])
	}
}

func vaultStatus(root string) error {
	raw, err := os.ReadFile(keyringPath(root))
	if os.IsNotExist(err) {
		if w.JSON(map[string]any{"encrypted": false}) {
			return nil
		}
		w.Human("there is no keyring, so no credential can be kept\n")
		w.Human("  %svaigil vault enable — make one%s\n", dim, reset)
		w.Human("  %sa connector's credentials and a feed's secret are sealed under it,\n"+
			"  so the files alone give nobody the values: a lost laptop, a backup\n"+
			"  on an open bucket, a disposed disk.%s\n", dim, reset)
		return nil
	}
	if err != nil {
		return err
	}
	kr := &vault.Keyring{}
	if err := json.Unmarshal(raw, kr); err != nil {
		return err
	}

	loaded := "no"
	if live, err := loadKeyring(root); err == nil && live != nil {
		loaded = "yes"
	}
	if w.JSON(map[string]any{
		"encrypted": true, "active": kr.Active, "keys": kr.IDs(),
		"material_loaded": loaded == "yes",
	}) {
		return nil
	}

	w.Human("credentials are sealed at rest\n")
	w.Human("  active key   %s%s%s\n", bold, kr.Active, reset)
	for _, id := range kr.IDs() {
		state := "active"
		if kr.Keys[id].Retired {
			state = "retired — still needed to read what it wrapped"
		}
		w.Human("  %-12s %s%s%s\n", id, dim, state, reset)
	}
	w.Human("  key loaded   %s\n", loaded)
	if loaded == "no" {
		w.Human("  %sset %s, %s or %s%s\n", yellow, keyEnv, keyFileEnv, keyCmdEnv, reset)
	}
	return nil
}

func vaultEnable(root string, args []string) error {
	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	id := fs.String("id", "k1", "an id for the first key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(keyringPath(root)); err == nil {
		return fmt.Errorf("this store already has a keyring; use vault rotate")
	}

	kr, err := vault.NewKeyring(*id, time.Now())
	if err != nil {
		return err
	}
	secret := vault.EncodeKey(kr.Keys[*id].Key)

	// The keyring on disk holds ids and metadata, never material. Writing the
	// key beside the data it protects would defeat the entire exercise, so it
	// is printed once and the operator has to put it somewhere.
	if err := saveJSON(keyringPath(root), kr); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "vault.enable", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{"kek_id": *id},
	})

	if w.JSON(map[string]any{"id": *id, "key": secret}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, secret, reset)
	w.Human("\n  %sthis is the only time it is shown. It is not stored here —\n"+
		"  a key kept beside the data it protects protects nothing against\n"+
		"  somebody who takes the directory.%s\n", yellow, reset)
	w.Human("\n  %ssupply it with one of:%s\n", dim, reset)
	w.Human("    export %s='%s'\n", keyEnv, "…")
	w.Human("    export %s=/run/secrets/vaigil.key\n", keyFileEnv)
	w.Human("    export %s='aws kms decrypt … --output text'\n", keyCmdEnv)
	w.Human("\n  %sa credential kept before this, in the clear, is sealed by:%s\n", dim, reset)
	w.Human("    vaigil vault rewrap\n")
	return nil
}

func vaultRotate(root string, args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	id := fs.String("id", "", "an id for the new key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		*id = fmt.Sprintf("k%d", time.Now().Unix())
	}

	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr == nil {
		return fmt.Errorf("this store has no keyring; use vault enable")
	}
	previous := kr.Active
	if err := kr.Add(*id, time.Now()); err != nil {
		return err
	}
	secret := vault.EncodeKey(kr.Keys[*id].Key)
	if err := saveJSON(keyringPath(root), kr); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "vault.rotate", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{"kek_id": *id, "previous": previous},
	})

	w.Human("%s%s%s\n", bold, secret, reset)
	w.Human("\n  %snew credentials are sealed with %s. %s is still needed to read\n"+
		"  everything written before now — supply both:%s\n",
		yellow, *id, previous, reset)
	w.Human("    export %s='%s=…,%s=…'\n", keyEnv, previous, *id)
	w.Human("\n  %sthen move what is already there:%s\n", bold, reset)
	w.Human("    vaigil vault rewrap\n")
	w.Human("\n  %suntil that runs, %s is still needed.%s\n", dim, previous, reset)
	return nil
}

// vaultRewrap seals every credential under the active key: one sealed
// under an older key is opened and sealed again, and one kept in the
// clear from before the keyring existed is sealed for the first time.
//
// Its own command because rotation is two steps, and each is safe on its
// own: after rotate every credential is still readable with the keys the
// operator already had, and during rewrap both keys are loaded by
// definition. A rewrap that stops half way is finished by running it
// again.
func vaultRewrap(root string, args []string) error {
	fs := flag.NewFlagSet("rewrap", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr == nil {
		return fmt.Errorf("this store has no keyring; use vault enable")
	}
	var moved, sealed int
	err = atomicfile.Update(secretsPath(root), func(f *sealedSecrets) error {
		if f.Sealed == nil {
			f.Sealed = map[string]json.RawMessage{}
		}
		for name, raw := range f.Sealed {
			s, err := vault.Unmarshal(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if s.KEK == kr.Active {
				continue
			}
			again, err := kr.Rewrap(s, []byte("connect/"+name))
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if f.Sealed[name], err = vault.Marshal(again); err != nil {
				return err
			}
			moved++
		}
		for name, value := range f.Plain {
			s, err := kr.Seal([]byte(value), []byte("connect/"+name))
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if f.Sealed[name], err = vault.Marshal(s); err != nil {
				return err
			}
			delete(f.Plain, name)
			sealed++
		}
		if moved+sealed == 0 {
			return atomicfile.ErrUnchanged
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w\n  nothing is lost: every credential is readable "+
			"with the keys you already have. Run this again to finish", err)
	}
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "vault.rewrap", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{"kek_id": kr.Active, "moved": fmt.Sprint(moved), "sealed": fmt.Sprint(sealed)},
	})
	w.Human("  %s%d credential(s) moved to %s, %d sealed for the first time%s\n",
		green, moved, kr.Active, sealed, reset)
	return nil
}
