// SPDX-License-Identifier: GPL-3.0-or-later
// mtk-logo-toolkit - MTK logo image toolchain
// Copyright (C) 2025 ELF-RC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Version and project metadata.
//!
//! Centralized version info so it can be updated in one place.
//! `--version` (long) prints the full banner; `-V` prints the short version.

/// Short version string (shown by `-V`).
pub const VERSION: &str = "1.5-dev";

/// Full version banner shown by `--version` (long form).
/// Note: clap automatically prepends the program name, so we omit it here.
pub const FULL_VERSION: &str = "1.5-dev
Authors: ELF-RC
License: GPL-3.0-or-later
Repository: https://github.com/ELF-RC/mtk_logo_toolkit
CVE: CVE-2023-20696 (legacy), CVE-2025-20730 (modern)";