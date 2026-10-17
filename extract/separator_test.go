// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package extract

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-eventlog/tcg"
)

// The PC Client spec allows two separator values: 00000000h and FFFFFFFFh.
var separatorValues = [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}

const separatorTypeErr = "contains separator data but non-separator type"

func TestGetSeparatorInfoDigests(t *testing.T) {
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384} {
		t.Run(hash.String(), func(t *testing.T) {
			info := getSeparatorInfo(hash)
			if len(info.separatorDigests) != len(separatorValues) {
				t.Fatalf("getSeparatorInfo() returned %d digests, want %d", len(info.separatorDigests), len(separatorValues))
			}
			for i, value := range separatorValues {
				hasher := hash.New()
				hasher.Write(value)
				want := hasher.Sum(nil)
				if got := info.separatorDigests[i]; !bytes.Equal(got, want) {
					t.Errorf("getSeparatorInfo() digest for %x = %x, want %x", value, got, want)
				}
			}
		})
	}
}

// A separator event with a changed type must be rejected for both separator
// values. Otherwise the parser would continue to trust events after the
// separator.
func TestPlatformStateRejectsRetypedSeparator(t *testing.T) {
	for _, sep := range separatorValues {
		t.Run(fmt.Sprintf("%x", sep), func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, 0, tcg.SCRTMVersion, []byte("pre-separator")),
				newEvent(t, 0, tcg.SCRTMVersion, sep),
				newEvent(t, 0, tcg.SCRTMVersion, []byte("post-separator")),
			})
			_, err := PlatformState(crypto.SHA256, events)
			if err == nil || !strings.Contains(err.Error(), separatorTypeErr) {
				t.Errorf("PlatformState() error = %v, want error containing %q", err, separatorTypeErr)
			}
		})
	}
}

func TestEfiStateRejectsRetypedSeparator(t *testing.T) {
	cfg := TPMRegisterConfig
	for _, sep := range separatorValues {
		t.Run(fmt.Sprintf("%x", sep), func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, cfg.EFIAppIdx, tcg.EFIAction, []byte(tcg.CallingEFIApplication)),
				newSeparatorEvent(t, cfg.EFIAppIdx),
				newEvent(t, cfg.EFIAppIdx, tcg.EFIBootServicesApplication, sep),
				newEvent(t, cfg.ExitBootServicesIdx, tcg.EFIAction, []byte(tcg.ExitBootServicesInvocation)),
			})
			_, err := EfiState(crypto.SHA256, events, cfg, Opts{})
			if err == nil || !strings.Contains(err.Error(), separatorTypeErr) {
				t.Errorf("EfiState() error = %v, want error containing %q", err, separatorTypeErr)
			}
		})
	}
}

// Separator events with the correct type must still pass for both values.
func TestPlatformStateAcceptsSeparator(t *testing.T) {
	for _, sep := range separatorValues {
		t.Run(fmt.Sprintf("%x", sep), func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, 0, tcg.SCRTMVersion, []byte("version")),
				newEvent(t, 0, tcg.Separator, sep),
			})
			state, err := PlatformState(crypto.SHA256, events)
			if err != nil {
				t.Fatalf("PlatformState() error = %v", err)
			}
			if got := string(state.GetScrtmVersionId()); got != "version" {
				t.Errorf("PlatformState() SCRTM version = %q, want %q", got, "version")
			}
		})
	}
}
