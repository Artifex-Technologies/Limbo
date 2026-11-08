package provision

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func winGuest() *manifest.Manifest {
	m := &manifest.Manifest{Name: "sctwin", OS: manifest.OSWindows}
	m.Access.User = "analyst"
	m.Provision.SSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample limbo-sctwin"
	return m
}

var hk = &HostKey{Private: "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n", Public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostHostHostHostHostHostHostHostHostHostHost limbo-sctwin"}

func TestWindowsAnswerFile(t *testing.T) {
	files, err := BuildWindows(winGuest(), WindowsOptions{Password: `pa<ss>&"word'123`, HostKey: hk})
	if err != nil {
		t.Fatal(err)
	}
	a := string(files["autounattend.xml"])
	// well formed, whatever the password holds
	if err := xml.Unmarshal(files["autounattend.xml"], new(struct{})); err != nil {
		t.Fatalf("not XML: %v", err)
	}
	for _, want := range []string{
		"BypassTPMCheck", "<WillWipeDisk>true</WillWipeDisk>", "<Value>1</Value>", "<AcceptEula>true</AcceptEula>",
		"<ComputerName>LIMBO-SCTWIN</ComputerName>", "<Name>analyst</Name>", "<fDenyTSConnections>false</fDenyTSConnections>",
		`pa&lt;ss&gt;&amp;&#34;word&#39;123`, "<HideOnlineAccountScreens>true</HideOnlineAccountScreens>",
		`for %d in (D E F G H I) do if exist %d:\limbo-setup.ps1`,
	} {
		if !strings.Contains(a, want) {
			t.Errorf("answer file lacks %s", want)
		}
	}
	if strings.Contains(a, "ProductKey") {
		t.Error("an evaluation has no product key")
	}
	if strings.Contains(a, `pa<ss>`) {
		t.Error("the password went in unescaped")
	}
	s := string(files[SetupScript])
	for _, want := range []string{"OpenSSH.Server", "administrators_authorized_keys", "fDisabledAllowList", "shutdown /s", "C:\\limbo-setup.done"} {
		if !strings.Contains(s, want) {
			t.Errorf("setup script lacks %s", want)
		}
	}
	if !strings.Contains(s, "\r\n") {
		t.Error("the script should have Windows line ends")
	}
	if string(files["administrators_authorized_keys"]) != winGuest().Provision.SSHPublicKey+"\r\n" {
		t.Errorf("authorized key: %q", files["administrators_authorized_keys"])
	}
	if !strings.HasPrefix(string(files["ssh_host_ed25519_key.pub"]), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHost") {
		t.Error("host key not passed through")
	}
}

func TestWindowsAnswerFileWithAKey(t *testing.T) {
	files, err := BuildWindows(winGuest(), WindowsOptions{Password: "correct horse battery", ProductKey: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", HostKey: hk, ImageIndex: 6})
	if err != nil {
		t.Fatal(err)
	}
	a := string(files["autounattend.xml"])
	if !strings.Contains(a, "<Key>ABCDE-FGHIJ-KLMNO-PQRST-UVWXY</Key>") || !strings.Contains(a, "<Value>6</Value>") {
		t.Errorf("key or edition missing:\n%s", a)
	}
}

func TestWindowsAnswerFileRefusals(t *testing.T) {
	ok := WindowsOptions{Password: "correct horse battery", HostKey: hk}
	lin := winGuest()
	lin.OS = manifest.OSLinux
	nokey := winGuest()
	nokey.Provision.SSHPublicKey = ""
	for name, c := range map[string]struct {
		m *manifest.Manifest
		o WindowsOptions
	}{
		"linux":         {lin, ok},
		"no ssh key":    {nokey, ok},
		"short":         {winGuest(), WindowsOptions{Password: "short", HostKey: hk}},
		"control chars": {winGuest(), WindowsOptions{Password: "correct horse\nbattery", HostKey: hk}},
		"bad key":       {winGuest(), WindowsOptions{Password: "correct horse battery", ProductKey: "ABCDE-12345", HostKey: hk}},
		"no host key":   {winGuest(), WindowsOptions{Password: "correct horse battery"}},
	} {
		if _, err := BuildWindows(c.m, c.o); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "ABCDE") {
			t.Errorf("%s: the key is in the error", name)
		}
	}
}
