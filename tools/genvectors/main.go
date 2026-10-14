// genvectors — testdata/pades-client/vectors.json-г build/go-sdk.ref цөмөөс үүсгэнэ:
//
//	./build/build-native.ps1 (эсвэл artifacts/go-sdk-д тэр commit-ийг clone) → cd tools/genvectors →
//	go run . ../../artifacts/go-sdk/pades/testdata/golden/desktop ../../testdata/pades-client ../../build/go-sdk.ref
//
// PKI нь шинээр (санамсаргүй) үүснэ — vector бүгд хамт солигдоно.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	src, out := os.Args[1], os.Args[2] // src = sdkgo/pades/testdata/golden/desktop, out = repo/testdata/pades-client
	must(os.MkdirAll(filepath.Join(out, "input"), 0o755))
	must(os.MkdirAll(filepath.Join(out, "pki"), 0o755))
	cp := func(rel, dst string) []byte {
		b, err := os.ReadFile(filepath.Join(src, rel))
		must(err)
		must(os.WriteFile(filepath.Join(out, dst), b, 0o644))
		return b
	}

	// Long-lived TEST-ONLY PKI (P-256), so CI does not depend on the 2-day desktop leaf.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nb, na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DOTNET PAdES Test Root", Country: []string{"MN"}},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &rootKey.PublicKey, rootKey)
	must(err)
	root, _ := x509.ParseCertificate(rootDER)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "TEST SIGNER", Country: []string{"MN"}},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, root, &leafKey.PublicKey, rootKey)
	must(err)
	pk8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	must(err)
	must(os.WriteFile(filepath.Join(out, "pki", "root.der"), rootDER, 0o644))
	must(os.WriteFile(filepath.Join(out, "pki", "leaf.der"), leafDER, 0o644))
	must(os.WriteFile(filepath.Join(out, "pki", "leaf.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}), 0o644))

	type prepVec struct {
		Name        string    `json:"name"`
		Input       string    `json:"input"`
		SignerName  string    `json:"signerName,omitempty"`
		Reason      string    `json:"reason,omitempty"`
		ClaimedRole string    `json:"claimedRole,omitempty"`
		SigningTime time.Time `json:"signingTime"`
		DocID       string    `json:"docId"`
		VerifyPage  bool      `json:"verifyPage"`
		FileName    string    `json:"fileName,omitempty"`
		Lang        string    `json:"lang,omitempty"`
		DTBS        string    `json:"dtbs"`
		Digest      string    `json:"digest"`
		StateSHA256 string    `json:"stateSha256"`
	}
	type verVec struct {
		Name   string          `json:"name"`
		Input  string          `json:"input"`
		Time   time.Time       `json:"time"`
		Report json.RawMessage `json:"report"`
	}
	inputs := map[string][]byte{
		"input/base-quartz.pdf": cp("input/base-quartz.pdf", "input/base-quartz.pdf"),
		"input/base-objstm.pdf": cp("input/base-objstm.pdf", "input/base-objstm.pdf"),
	}
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.FixedZone("", 8*3600))
	preps := []prepVec{
		{Name: "quartz-plain", Input: "input/base-quartz.pdf", SignerName: "TEST SIGNER", Reason: "Гэрээ баталгаажуулав", SigningTime: t0, DocID: "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{Name: "objstm-role", Input: "input/base-objstm.pdf", SignerName: "TEST SIGNER", ClaimedRole: "Гүйцэтгэх захирал", SigningTime: t0, DocID: "7c9e6679-7425-40de-944b-e07fc1f90ae7"},
		{Name: "quartz-verify-page", Input: "input/base-quartz.pdf", SigningTime: t0, DocID: "1b4e28ba-2fa1-41d2-883f-0016d3cca427", VerifyPage: true, FileName: "гэрээ.pdf", Lang: "mn"},
	}
	for i := range preps {
		v := &preps[i]
		p, err := pades.Prepare(inputs[v.Input], pades.PrepareOptions{SignerCert: leafDER, Chain: [][]byte{rootDER}, SignerName: v.SignerName,
			Reason: v.Reason, ClaimedRole: v.ClaimedRole, SigningTime: v.SigningTime, DocID: v.DocID, VerifyPage: v.VerifyPage, FileName: v.FileName, Lang: v.Lang})
		must(err)
		// determinism check
		p2, err := pades.Prepare(inputs[v.Input], pades.PrepareOptions{SignerCert: leafDER, Chain: [][]byte{rootDER}, SignerName: v.SignerName,
			Reason: v.Reason, ClaimedRole: v.ClaimedRole, SigningTime: v.SigningTime, DocID: v.DocID, VerifyPage: v.VerifyPage, FileName: v.FileName, Lang: v.Lang})
		must(err)
		if hex.EncodeToString(p.DTBS) != hex.EncodeToString(p2.DTBS) {
			panic("non-deterministic " + v.Name)
		}
		s := sha256.Sum256(p.State)
		v.DTBS, v.Digest, v.StateSHA256 = hex.EncodeToString(p.DTBS), hex.EncodeToString(p.Digest), hex.EncodeToString(s[:])
	}

	// Verify: desktop golden outputs (their own test root), fixed time.
	dRoot, _ := pem.Decode(cp("pki/root.pem", "pki/desktop-root.pem"))
	tv := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	var vers []verVec
	for _, n := range []string{"quartz-1-dss.pdf", "quartz-2-dss.pdf", "objstm-2-dss.pdf"} {
		b := cp("output/"+n, "input/"+n)
		r, err := pades.Verify(b, pades.VerifyOptions{Roots: [][]byte{dRoot.Bytes}, Time: tv})
		must(err)
		j, err := json.Marshal(r)
		must(err)
		vers = append(vers, verVec{Name: n, Input: "input/" + n, Time: tv, Report: j})
	}
	commit, _ := os.ReadFile(os.Args[3])
	doc := map[string]any{"coreCommit": strings.TrimSpace(string(commit)), "profile": pades.ProfileVersion, "prepare": preps, "verify": vers}
	j, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "vectors.json"), append(j, '\n'), 0o644))
}
