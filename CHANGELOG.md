# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)

## [Unreleased]

## [1.3.2] - 2022-12-12
### Changed
 - Header minimization (see https://github.com/ngo/burp-request-minimizer/pull/9)

## [1.3.1] - 2021-08-01
### Fixed
 - POST parameters minimization (see https://github.com/ngo/burp-request-minimizer/issues/7)

## [1.3] - 2018-06-20
### Changed
 - Removed xerces jar dependency, uses jython's jar instead
### Fixed
 - Wrong import in testserver

## [1.2] - 2018-06-19
### Added
 - XML and JSON request minimization (see #2)
 - Test webapp for json and xml minimization
 - Changelog file

## [1.1] - 2018-06-06
### Fixed
 - Exception on XML and json parameters (see #1)

## [1.0] - 2017-06-23
### Added
 - Initial minimizer version
