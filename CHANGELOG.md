# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [3.2.4] 2026-09-02
### Fixed
- Restored `Id` as the group permission identifier in the membership import, allowing imported memberships to correlate with permissions identified by `Identification.Id`.
- Corrected group-query pagination in the permission import, membership import, and subpermission scripts.
- Corrected group display name formatting and limited imported membership descriptions to 100 characters.

### Changed
- Updated the README to document the Zenya provider migration process and the SCIM and REST API visibility limitations.

## [3.2.3]  2026-08-17
### Added
   - Add phone number to account mapping and scripts

### Changed
   - Update readme with extra instruction

### Removed
   - Remove SCIM version of resource script

## [3.2.2]  2026-06-15
### Changed
   - Fix revoke membership in subpermissions

## [3.2.1]  2026-03-06
### Changed
   - Updated the readme to not refer to Zenya settings which have been deprecated

## [3.2.0]  2026-02-12
### Changed
   - Added strict_validation parameter to group creation API request
   - Added start_portal parameter with value 100 to group creation request body

## [3.1.0]  2026-01-22
### Changed
   - Fix:  In version 3.0.0 the permission reference field name was accidentally renamed (from ".Id" to .Reference). This has been rolled back.

## [3.0.0]  2026-01-15
### Added 
 - Added permission import script for groups 
### Changed
 -  All permission management operations now use the REST API instead of the SCIM api, to allow for the management of existing groups.

### [2.3.1]

### Changed

- Fix:  Streamlines user import by processing each page of users as they are retrieved, removing the need to accumulate all users in an intermediate array. This reduces memory usage and simplifies the logic for mapping and outputting user data.


## [2.3.0] 2025-09-03

### Added
- Added Reconciliation to disable by @sjoerdvandijkt4e 


## [2.2.0] 2025-06-04

### Changed
- Fixes after implementation by @rhouthuijzen 

## [2.1.0] 2024-11-22

### Changed

- fix: skip value was updated with non existing variable by @mspreeuwenberg 
- Update readme by @mouki9 
- Refactor code formatting and repo structure by @rschouten97 

## [2.0.1] 2024-04-09

### Changed
- PS v2 release by @rschouten97 in #6
- Fix resource creation by @mspreeuwenberg in #8

## [1.1.3] 1023-24-27

### Added

- Feat-add-dynamicpermissons by @rschouten97 

### Changed
- Updated logging by @rschouten97
- Updated create.ps1 by @Rick-Jongbloed
- Updated readme by @rschouten97 

## [1.0.0] - n.a

### Added

### Changed

### Deprecated

### Removed
