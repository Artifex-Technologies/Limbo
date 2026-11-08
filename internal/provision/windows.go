package provision

// Windows guests: an unattended answer file (autounattend.xml) and the script it runs at first logon, for a Windows
// guest installed from the user's own ISO (package license is the gate in front of it). `limbo seed` puts these files on
// a small CD next to the installation ISO; Windows Setup finds autounattend.xml on it by itself.
//
// What the guest gets: one local administrator (the manifest's access.user) with the password given here, no Microsoft
// account and no online screens, Remote Desktop on with RemoteApp allowed for any program (how `limbo launch` shows an
// application), Windows' own OpenSSH server with Limbo's key and a host key made on the host (so the host pins it before
// the guest ever boots, as for Linux guests), no sleep or hibernation. When the script is done the guest shuts down: the
// installation is finished, and `limbo export` turns its disk into a base image.
//
// Windows 11's TPM 2.0, Secure Boot and memory checks are skipped (Setup's LabConfig switches): Limbo's guests boot with
// SeaBIOS and have no TPM. That suits lab guests that run one program; it is not a supported Windows configuration.
//
// Written 2026-11-08 against Windows 11 Enterprise LTSC 2024 (build 26100), the evaluation edition.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// WindowsOptions are what a Windows guest's answer file needs besides its manifest.
type WindowsOptions struct {
	// Password of the local account (access.user): 12 to 127 printable characters. Kept beside the seed, root-only;
	// `limbo launch` asks for it (RDP), and it is never put in a manifest.
	Password string
	// ProductKey is the license's key (five groups of five), or "" for an edition that takes none (an evaluation).
	ProductKey string
	// HostKey is the guest's sshd host key pair, made on the host (required: the manifest pins its public half).
	HostKey *HostKey
	// ImageIndex picks the edition inside the ISO's install.wim (1 when it holds one).
	ImageIndex int
}

var (
	productKeyRe = regexp.MustCompile(`^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`)
	computerRe   = regexp.MustCompile(`[^A-Z0-9-]`)
)

// SetupScript is the name of the first-logon script on the seed CD.
const SetupScript = "limbo-setup.ps1"

// BuildWindows renders the seed CD's files: autounattend.xml, the first-logon script, the authorized key and the host
// key pair. Every value is checked first and XML-escaped where it goes into the answer file.
func BuildWindows(m *manifest.Manifest, o WindowsOptions) (map[string][]byte, error) {
	if m.OS != manifest.OSWindows {
		return nil, fmt.Errorf("provision: not a Windows guest")
	}
	if !keyRe.MatchString(m.Provision.SSHPublicKey) {
		return nil, fmt.Errorf("provision: provision.ssh_public_key missing or not a single-line public key")
	}
	if n := len([]rune(o.Password)); n < 12 || n > 127 || strings.IndexFunc(o.Password, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return nil, fmt.Errorf("provision: the Windows password must be 12 to 127 printable characters")
	}
	if o.ProductKey != "" && !productKeyRe.MatchString(o.ProductKey) {
		return nil, fmt.Errorf("provision: not a Windows product key") // never the key itself
	}
	if o.HostKey == nil || !keyRe.MatchString(o.HostKey.Public) || !strings.Contains(o.HostKey.Private, "PRIVATE KEY") {
		return nil, fmt.Errorf("provision: a Windows guest needs its host key pair")
	}
	index := o.ImageIndex
	if index <= 0 {
		index = 1
	}
	// NetBIOS names: at most 15 characters, letters, digits and hyphens
	computer := computerRe.ReplaceAllString(strings.ToUpper("LIMBO-"+m.Name), "-")
	if len(computer) > 15 {
		computer = computer[:15]
	}
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	key := ""
	if o.ProductKey != "" {
		key = "\n        <ProductKey>\n          <Key>" + o.ProductKey + "</Key>\n          <WillShowUI>Never</WillShowUI>\n        </ProductKey>"
	}
	user, pass := esc(m.Access.User), esc(o.Password)
	answer := fmt.Sprintf(answerFile, index, key, computer, user, pass, user, pass, SetupScript, SetupScript)

	pub := strings.TrimSpace(o.HostKey.Public)
	return map[string][]byte{
		"autounattend.xml":               []byte(answer),
		SetupScript:                      []byte(strings.ReplaceAll(setupScript, "\n", "\r\n")),
		"administrators_authorized_keys": []byte(strings.TrimSpace(m.Provision.SSHPublicKey) + "\r\n"),
		"ssh_host_ed25519_key":           []byte(o.HostKey.Private),
		"ssh_host_ed25519_key.pub":       []byte(pub + "\n"),
	}, nil
}

// answerFile: windowsPE (language, the checks skipped, the whole disk as one partition, the edition, the key),
// specialize (name, time zone, Remote Desktop and its firewall rule), oobeSystem (no online screens, the local account,
// one automatic logon that runs the script from whichever drive the seed CD got).
const answerFile = `<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
              <Active>true</Active>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/INDEX</Key>
              <Value>%d</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>1</PartitionID>
          </InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>%s
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>%s</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
    <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <FirewallGroups>
        <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
          <Active>true</Active>
          <Group>Remote Desktop</Group>
          <Profile>all</Profile>
        </FirewallGroup>
      </FirewallGroups>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>%s</Name>
            <Group>Administrators</Group>
            <Password>
              <Value>%s</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>%s</Username>
        <Password>
          <Value>%s</Value>
          <PlainText>true</PlainText>
        </Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c for %%d in (D E F G H I) do if exist %%d:\%s powershell -NoProfile -ExecutionPolicy Bypass -File %%d:\%s</CommandLine>
          <Description>Limbo's setup</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
`

// setupScript runs once, at the first logon, from the seed CD. It logs to C:\limbo-setup.log and ends by shutting the
// guest down, which is how `limbo` knows the installation is finished.
const setupScript = `$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\limbo-setup.log
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# no sleep, no hibernation (and so no fast startup): a guest is started and stopped from outside
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /hibernate off

# RemoteApp for any program: limbo launch shows one application as a window over RDP
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList" /v fDisabledAllowList /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnlistedRemotePrograms /t REG_DWORD /d 1 /f

# Limbo's private network is trusted inside the guest (the host's rules decide what it may reach)
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# Windows' own OpenSSH server (a Windows feature, fetched from Windows Update), with Limbo's keys
$ok = $false
for ($i = 0; $i -lt 10 -and -not $ok; $i++) {
  try {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop | Out-Null
    $ok = $true
  } catch {
    Write-Output "OpenSSH not installed yet ($_); trying again in 30 s"
    Start-Sleep -Seconds 30
  }
}
$ssh = 'C:\ProgramData\ssh'
New-Item -ItemType Directory -Force -Path $ssh | Out-Null
foreach ($f in 'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'administrators_authorized_keys') {
  Copy-Item -Force (Join-Path $here $f) (Join-Path $ssh $f)
}
foreach ($f in 'ssh_host_ed25519_key', 'administrators_authorized_keys') {
  icacls (Join-Path $ssh $f) /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F'
}
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Write-Output "sshd: $((Get-Service sshd).Status)"

New-Item -ItemType File -Force -Path C:\limbo-setup.done | Out-Null
Stop-Transcript
shutdown /s /t 15 /c "Limbo: setup finished"
`
