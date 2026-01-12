# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).


### [3.0.0]  2026-01-15

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