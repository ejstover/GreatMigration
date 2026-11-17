# Quickstart release validation

Automated launcher tests use synthetic installations, temporary local Git sources,
and mocked native service operations. They do not register tasks/services on the
developer's computer. Run `python -m pytest tests/test_quickstart.py -q`.

CI runs the launcher tests on Windows, Linux, and macOS. This verifies parsing,
definitions, local Git behavior, and mocked lifecycle behavior; it does not prove
native boot installation works on each OS.

## Native service smoke tests (disposable machines only)

For each of Windows, systemd Linux, and macOS, use a disposable VM with Python 3.11,
a stable local checkout (include spaces in the path), synthetic local credentials,
and no production Mist/LDAP/device credentials:

1. Run `setup --no-start --no-autostart`. Verify existing configuration/account
   files survive repeated setup and normal foreground startup works offline.
2. Run `autostart enable` as the ordinary app user. Verify elevation is limited to
   OS registration/control; the app process runs as that user. On Windows, verify
   the native credential prompt, cancellation, bad password, and denied batch logon.
3. Run `start`, inspect `status` and the service log, and sign in locally. Repeat
   `start` and confirm only one worker/instance is running. Verify `stop` closes the
   listener and `restart` starts it again. Test an occupied port/startup failure.
4. Reboot without signing in. From a second machine or OS service instrumentation,
   confirm startup before sign-in (use explicitly reviewed host/firewall settings
   if remote access is needed). Do not expose a test HTTP listener publicly.
5. Deliberately fail application startup; verify retry delays and the limit. Repair
   the issue and verify explicit `start` clears the retry limit.
6. Use a temporary local fork/branch with a compatible newer revision. Verify a
   running service is stopped, upgraded, and restarted; `upgrade --no-start` and
   upgrades of stopped services leave it stopped. Verify dirty/divergent/fetch
   failures leave a running service untouched; dependency failure leaves it stopped
   with the correct recovery journal. Restore using the documented manual process.
7. Run `autostart disable`, verify process exit/registration removal, and reboot
   again to confirm the app stays stopped. Repeated disable is harmless.

Record OS/version, account type, results, and log excerpts with secrets removed.
Do not claim native service or reboot validation from mocked CI results alone.
