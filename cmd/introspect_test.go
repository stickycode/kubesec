package cmd

import (
	"github.com/shyiko/kubesec/gpg"
	"reflect"
	"testing"
	// log "github.com/sirupsen/logrus"
	"os"
)

func TestIntrospectUnencrypted(t *testing.T) {
	if _, err := Introspect([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n")); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "Not encrypted"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}

func TestIntrospect(t *testing.T) {
	os.Setenv("HOME", "../")
	gpg.SetPassphrase("test")
	gpg.SetKeyring("test.keyring")

	expected := []string{
		"4459A441306219F88CD7581E1A5669F6742AE4E2",
		"58C0E6EC8AF3DD8CDB8DFF5F855409ED748CE5B1",
	}
	encrypted, err := EncryptWithContext([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n"), EncryptionContext{
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, expected[0]}, nil},
			KeyWithDEK{Key{KTPGP, expected[1]}, nil},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := reconstructEncryptionContext(encrypted, false, false)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := keyIds(ctx, KTPGP)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}
