# dfir-osint-toolkit

Build scripts for a DFIR and OSINT analysis setup: a Windows forensic workstation plus a Kali Linux environment (bare metal, VM or WSL2). Both scripts can be re-run safely, keep going if a single tool fails, and print a summary at the end.

| Script | Platform | Installs |
|---|---|---|
| [`windows/Install-DFIRTools.ps1`](windows/Install-DFIRTools.ps1) | Windows 10/11, elevated PowerShell 5.1+ | **winget:** Git, Python 3.12 (+ Volatility 3), VS Code, Wireshark, 7-Zip, Notepad++, Sysinternals<br>**Downloads:** Eric Zimmerman tools (MFTECmd, PECmd, Registry Explorer, Timeline Explorer, ...) and Autopsy |
| [`kali/install-kali-dfir-osint.sh`](kali/install-kali-dfir-osint.sh) | Kali Linux / Kali on WSL2, run with `sudo` | **apt:** sleuthkit, plaso, yara, bulk-extractor, binwalk, foremost, exiftool, hashcat, john, tshark, nmap<br>**OSINT:** theHarvester, recon-ng, sherlock<br>**pipx:** volatility3, maigret, holehe<br>**Go:** amass, subfinder, httpx, nuclei, assetfinder, waybackurls, gau |

## Folder layout

**Windows** (`-BaseDir`, default `C:\DFIR`):

```
C:\DFIR\
  Tools\EZTools\   Cases\   MemoryDumps\   Scripts\   Logs\   (install transcript)
```

**Kali**, created in the home folder of the user who ran `sudo`, not root's:

```
~/DFIR/{Tools,Cases,Scripts,Logs}   ~/OSINT
~/DFIR/Scripts/update-all-tools.sh   # apt + pipx + go updates
```

## Usage

```powershell
# Windows, elevated
Set-ExecutionPolicy -Scope Process Bypass
.\windows\Install-DFIRTools.ps1                 # default C:\DFIR
.\windows\Install-DFIRTools.ps1 -BaseDir D:\DFIR
```

```bash
# Kali / WSL2
chmod +x kali/install-kali-dfir-osint.sh
sudo ./kali/install-kali-dfir-osint.sh
```

With WSL2 you can run the Linux tools (plaso, bulk_extractor, sleuthkit) directly against evidence on the Windows side under `/mnt/c/DFIR/Cases`.

## Design notes

- **User-level tools go to the real user.** The Kali script resolves `SUDO_USER`, so pipx and `go install` run as that user and the folders are owned by them. Otherwise everything lands in `/root`.
- **Kali packages first.** theHarvester, recon-ng and sherlock come from Kali's apt repos, which track Kali's Python. pipx is used only for tools that Kali does not package.
- **No PATH refresh needed.** On Windows, the Volatility 3 install uses the `py` launcher, so it works in the same session that just installed Python.
- **Package checks** use `dpkg-query` on Kali and `winget list --exact` on Windows. Installed packages are skipped.

## Caveats

- AV/EDR will flag some of these tools (PsExec, password crackers, memory tools). On a dedicated analysis box, add an exclusion for the tools folder. Don't do this on a daily-driver machine.
- Autopsy is pinned to a version in the script. Bump `$AutopsyVersion` when a new release comes out.
- PhoneInfoga is distributed as a release binary. The Kali script tells you where to get it rather than installing it.
- For OSINT work, use a dedicated VM or browser profile and route traffic through a VPN or proxy.

## Testing

- `install-kali-dfir-osint.sh` passes `bash -n` and `shellcheck`.
- `Install-DFIRTools.ps1` parses and passes PSScriptAnalyzer. It is Windows-only and **tested for syntax only** in this repo.

## License

MIT, see [LICENSE](LICENSE).
