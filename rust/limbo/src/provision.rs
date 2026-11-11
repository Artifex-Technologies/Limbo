//! The cloud-init seed for a validation run's Linux guest (Go: internal/provision, Build). Every value is validated and
//! written as a JSON string (JSON is YAML), so no value can change the document's structure.

use crate::gojson::str_json as q;
use crate::manifest::{self, Manifest};

pub struct Seed {
    pub user_data: String,
    pub meta_data: String,
}

/// `^[A-Za-z0-9][A-Za-z0-9+._-]*$`
fn pkg_ok(p: &str) -> bool {
    let b = p.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'_' | b'-'))
}

/// `^(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/=]+( [^\r\n]*)?$`
fn key_ok(k: &str) -> bool {
    let alg_end = match k.find(' ') {
        Some(i) => i,
        None => return false,
    };
    let alg = &k[..alg_end];
    let lower_digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let alg_ok = alg.strip_prefix("ssh-").is_some_and(lower_digits) || alg.strip_prefix("ecdsa-sha2-").is_some_and(lower_digits);
    if !alg_ok {
        return false;
    }
    let rest = &k[alg_end + 1..];
    let n = rest.bytes().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')).count();
    if n == 0 {
        return false;
    }
    let tail = &rest[n..];
    tail.is_empty() || (tail.starts_with(' ') && !tail.contains(['\r', '\n']))
}

pub fn build(m: &Manifest) -> Result<Seed, String> {
    build_with_host_key(m, None)
}

/// Go's BuildWithHostKey: [`build`] plus the guest's own host key pair (private, public, as the files hold them).
pub fn build_with_host_key(m: &Manifest, hk: Option<(&[u8], &[u8])>) -> Result<Seed, String> {
    if m.os != manifest::OS_LINUX {
        return Err("provision: only Linux guests are supported".into());
    }
    if !key_ok(&m.provision.ssh_public_key) {
        return Err("provision: provision.ssh_public_key missing or not a single-line public key".into());
    }
    let pkgs = m.provision.packages.as_deref().unwrap_or(&[]);
    for p in pkgs {
        if !pkg_ok(p) {
            return Err(format!("provision: invalid package name {}", crate::gotext::quote(p)));
        }
    }
    let mut b = String::from("#cloud-config\nusers:\n");
    b.push_str(&format!("  - name: {}\n", q(&m.access.user)));
    b.push_str("    lock_passwd: true\n    shell: /bin/bash\n");
    if m.access.sudo {
        b.push_str("    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n");
    }
    b.push_str(&format!("    ssh_authorized_keys: [{}]\n", q(&m.provision.ssh_public_key)));
    if let Some((private, public)) = hk {
        let public = crate::cli::commands::trim_space(public);
        if !manifest::host_key_ok(&crate::gotext::lossy(public)) || !private.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
            return Err("provision: the host key pair is not an ed25519 OpenSSH key".into());
        }
        b.push_str("ssh_deletekeys: true\nssh_genkeytypes: []\nssh_keys:\n");
        b.push_str(&format!("  ed25519_private: {}\n", crate::cli::commands::json_bytes(private)));
        b.push_str(&format!("  ed25519_public: {}\n", crate::cli::commands::json_bytes(public)));
    }
    b.push_str("disable_root: true\nssh_pwauth: false\n");
    b.push_str("bootcmd:\n  - [systemctl, mask, --now, systemd-time-wait-sync.service]\n");
    if pkgs.is_empty() {
        b.push_str("package_update: false\npackage_upgrade: false\n");
    } else {
        b.push_str("package_update: true\npackages:\n");
        for p in pkgs {
            b.push_str(&format!("  - {}\n", q(p)));
        }
    }
    let meta = format!("instance-id: {}\nlocal-hostname: {}\n", q(&format!("limbo-{}", m.name)), q(&m.name));
    Ok(Seed { user_data: b, meta_data: meta })
}

// ---- Windows guests (Go: internal/provision/windows.go) ----

/// What a Windows guest's answer file needs besides its manifest.
pub struct WindowsOptions {
    /// The local account's password: 12 to 127 printable characters.
    pub password: String,
    /// The license's key, or "" for an edition that takes none.
    pub product_key: String,
    /// The guest's sshd host key pair, made on the host: (private, public), as the files hold them.
    pub host_key: Option<(Vec<u8>, Vec<u8>)>,
    /// The edition inside the ISO's install.wim (1 when 0 or less).
    pub image_index: i64,
}

/// The first-logon script's name on the seed CD.
pub const SETUP_SCRIPT: &str = "limbo-setup.ps1";

/// `^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`
fn product_key_ok(k: &str) -> bool {
    let b = k.as_bytes();
    b.len() == 29 && b.iter().enumerate().all(|(i, &c)| if i % 6 == 5 { c == b'-' } else { c.is_ascii_uppercase() || c.is_ascii_digit() })
}

/// Go's xml.EscapeText.
fn xml_esc(s: &str) -> String {
    let mut out = String::new();
    crate::virt::esc_text(s, &mut out);
    out
}

/// fmt.Sprintf of the answer file: each %d and %s in turn, %% as %.
fn fill(t: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(t.len() + 256);
    let mut it = args.iter();
    let mut rest = t;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        match rest.as_bytes().get(i + 1) {
            Some(b'%') => out.push('%'),
            _ => out.push_str(it.next().map(String::as_str).unwrap_or("")),
        }
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out
}

/// The seed CD's files (name, content), in the order they are written: the answer file, the first-logon script, the
/// authorized key and the host key pair.
pub fn build_windows(m: &Manifest, o: &WindowsOptions) -> Result<Vec<(String, Vec<u8>)>, String> {
    if m.os != manifest::OS_WINDOWS {
        return Err("provision: not a Windows guest".into());
    }
    if !key_ok(&m.provision.ssh_public_key) {
        return Err("provision: provision.ssh_public_key missing or not a single-line public key".into());
    }
    let n = o.password.chars().count();
    if !(12..=127).contains(&n) || o.password.chars().any(|c| !crate::gotext::is_print(c)) {
        return Err("provision: the Windows password must be 12 to 127 printable characters".into());
    }
    if !o.product_key.is_empty() && !product_key_ok(&o.product_key) {
        return Err("provision: not a Windows product key".into());
    }
    let pair_ok = |(p, pubk): &&(Vec<u8>, Vec<u8>)| key_ok(&crate::gotext::lossy(pubk)) && p.windows(11).any(|w| w == b"PRIVATE KEY");
    let Some((private, public)) = o.host_key.as_ref().filter(pair_ok) else {
        return Err("provision: a Windows guest needs its host key pair".into());
    };
    let index = if o.image_index <= 0 { 1 } else { o.image_index };
    let mut computer: String = format!("LIMBO-{}", crate::gotext::to_upper(&m.name))
        .chars()
        .map(|c| if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' { c } else { '-' })
        .collect();
    if computer.len() > 15 {
        computer = crate::gotext::byte_prefix(&computer, 15);
    }
    let key = if o.product_key.is_empty() {
        String::new()
    } else {
        format!(
            "\n        <ProductKey>\n          <Key>{}</Key>\n          <WillShowUI>Never</WillShowUI>\n        </ProductKey>",
            o.product_key
        )
    };
    let (user, pass) = (xml_esc(&m.access.user), xml_esc(&o.password));
    let answer = fill(
        ANSWER_FILE,
        &[index.to_string(), key, computer, user.clone(), pass.clone(), user, pass, SETUP_SCRIPT.into(), SETUP_SCRIPT.into()],
    );
    let mut public = crate::cli::commands::trim_space(public).to_vec();
    public.push(b'\n');
    Ok(vec![
        ("autounattend.xml".into(), answer.into_bytes()),
        (SETUP_SCRIPT.into(), SETUP_SCRIPT_TEXT.replace('\n', "\r\n").into_bytes()),
        ("administrators_authorized_keys".into(), format!("{}\r\n", crate::gotext::trim_space(&m.provision.ssh_public_key)).into_bytes()),
        ("ssh_host_ed25519_key".into(), private.clone()),
        ("ssh_host_ed25519_key.pub".into(), public),
    ])
}

/// The answer file (Go's answerFile, a Sprintf template).
const ANSWER_FILE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
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
"#;

/// The first-logon script (Go's setupScript), written with CRLF line ends.
const SETUP_SCRIPT_TEXT: &str = r#"$ErrorActionPreference = 'Continue'
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
# every network profile: a guest started from the finished image has a new network card address, so Windows sees a new
# network, calls it Public, and a rule for Private only would drop Limbo's connections (seen 2026-11-08)
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
}
Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Profile Any -Enabled True
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Write-Output "sshd: $((Get-Service sshd).Status)"

New-Item -ItemType File -Force -Path C:\limbo-setup.done | Out-Null
Stop-Transcript
shutdown /s /t 15 /c "Limbo: setup finished"
"#;
