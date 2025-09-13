# f2b Project Overview

## Purpose

f2b is an **enterprise-grade Go CLI wrapper** for managing [Fail2Ban](https://www.fail2ban.org/) jails and bans.
Modern, secure, and extensible tool providing:

- **Comprehensive command set** for Fail2Ban management
- **Advanced security features** including extensive path traversal protections
- **Context-aware timeout support** with graceful cancellation
- **Real-time performance monitoring** and metrics collection
- **Multi-architecture Docker deployment** support
- **Modern fluent testing infrastructure** with significant code reduction

## Current Status (2025-09-13)

- **Go Version**: 1.25.0 (latest stable)
- **Build Status**: ✅ All tests passing, 0 linting issues
- **Dependencies**: ✅ All updated to latest versions
- **Test Coverage**: Comprehensive coverage across all packages - Above industry standards
- **Security**: ✅ All validation tests passing

## Core Architecture

### Structure

- **main.go**: Entry point with secure initialization
- **cmd/**: Comprehensive set of Cobra CLI commands
  - Core: ban, unban, status, list-jails, banned, test
  - Advanced: logs, logs-watch, metrics, service, test-filter
  - Utility: version, completion
- **fail2ban/**: Enterprise client logic with interfaces

### Design Principles

- **Security-First**: Extensive path traversal protections, zero shell injection, context-aware timeouts
- **Performance-Optimized**: Validation caching, parallel processing, object pooling
- **Interface-Based**: Full dependency injection for testing and extensibility
- **Modern Testing**: Fluent framework with substantial code reduction

## Tech Stack

- **Language**: Go 1.25+ with modern idioms
- **CLI Framework**: Cobra with comprehensive command structure
- **Logging**: Structured logging with Logrus
- **Testing**: Advanced mock patterns with thread-safe implementations
- **Deployment**: Multi-architecture Docker support

## Key Features

- **Smart Privilege Management**: Automatic sudo detection and minimal escalation
- **Context-Aware Operations**: Timeout handling prevents hanging
- **Comprehensive Security**: Extensive input validation and attack protection
- **Modern Testing Framework**: Fluent API with significant code reduction
- **Real-Time Monitoring**: Performance metrics and system monitoring
- **Multi-Architecture**: Docker support for amd64, arm64, armv7
