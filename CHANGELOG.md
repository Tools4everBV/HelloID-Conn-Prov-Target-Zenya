# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).


# Changelog

## [2.3.1] - 18-11-2025

### Fixed
- Streamlines user import by processing each page of users as they are retrieved, removing the need to accumulate all users in an intermediate array. This reduces memory usage and simplifies the logic for mapping and outputting user data.

## [2.3.0] - 2025-01-10
### Recent Updates (2024–2025)
- Added reconciliation functionality.
- Implemented dynamic permissions.
- Added support for group creation and group management.
- Updated README with new information.

---

## [2.1.0] - 2024-08-05
### Bug Fixes and Improvements (2024)
- Fixed issues with skip values in scripts.
- Improved group creation checks.
- Updated documentation and README files.

---

## [2.0.1] - 2024-03-20
### PowerShell v2 Release (2024)
- Major release of PowerShell v2 connector.
- Added `icon.png` for visual representation.
- Updated `create.ps1` script.

---

## [1.1.3] - 2023-10-15

### Connector Enhancements (2023–2024)
- Added dynamic permissions script.
- Implemented fixes for resource creation.
- Updated README with connector logo and documentation.
- Added support for department limitations and remarks.
- Added localization files:
  - `INFO_NL.md`
  - `INFO_FR.md`

---

## [1.0.0] - 2022-12-01

### Initial Setup (2022–2023)
- Created initial repository with basic connector functionality.
- Added support for:
  - Title
  - Manager
  - Department
- Implemented logging of updated properties.
- Added support for HTTP error resolving.