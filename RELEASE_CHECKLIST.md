# Release Checklist

- [ ] All tests pass: `python -m unittest discover -s tests`
- [ ] Manual smoke test of GUI on Windows and Linux
- [ ] Verify `ghost_sniffer.log` is created and populated
- [ ] Confirm README instructions and legal warnings are current
- [ ] Update `CHANGELOG.md` with release notes
- [ ] Tag the release in Git (e.g. `v1.0.0`)
- [ ] Build and verify package: `python -m build`
- [ ] Build Windows executable: `scripts\build_windows.bat`