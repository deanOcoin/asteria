`Asteria.app` for Apple Silicon Macs, macOS 14 or newer. Xcode or the Command Line Tools must be installed: the app drives LLVM and LLDB from the system toolchain at runtime.

The build is ad-hoc signed and not notarised, so Gatekeeper will object on first launch. Either right-click the app and choose Open, or clear the quarantine flag after unzipping:

```sh
xattr -dr com.apple.quarantine Asteria.app
```

Debugging another process needs the usual developer-tools authorisation; Asteria does not bypass SIP or hardened-runtime restrictions. Release notes for every version are in `docs/RELEASE_NOTES.md`.
