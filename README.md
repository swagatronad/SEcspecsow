# SecScan

Android security scanner project.

## Build
Use the repository's GitHub Actions workflow in `.github/workflows/`. Open **Actions** and download the APK artifact after a successful build.

## Permission behavior
SecScan should not silently grant protected Android permissions using root shell commands. Usage access and notification permissions should be enabled by the user through Android settings/system UI.
