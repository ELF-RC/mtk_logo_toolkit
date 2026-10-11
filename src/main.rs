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

mod part_header;
mod asn1_der;
mod image_codec;
mod logo_payload;
mod cert_inject;

use std::path::Path;
use clap::{Parser, Subcommand};
use cert_inject::BypassMode;

const VERSION: &str = "1.5-dev";

/// Returns the program basename from argv[0], for use in help hints.
fn prog_name() -> String {
    std::env::args()
        .next()
        .as_deref()
        .map(|s| {
            std::path::Path::new(s)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| s.to_string())
        })
        .unwrap_or_else(|| "mtk-logo-toolkit".to_string())
}

/// MTK logo image toolchain: unpack / pack / install / build / verify
#[derive(Parser)]
#[command(version = VERSION)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract logo chunks to PNG/.rgba
    Unpack {
        /// Input logo image file
        image: String,
        /// Output directory (default <stem>_out)
        #[arg(short = 'o', long)]
        out: Option<String>,
    },
    /// Repack images (PNG/BMP/JPG/GIF/TGA/PNM) into a logo image; auto fit
    Pack {
        /// Directory of edited chunks (indexed by filename prefix)
        dir: String,
        /// Original logo image as template
        template: String,
        /// Output file (default <template>.packed)
        #[arg(short = 'o', long)]
        out: Option<String>,
    },
    /// Inject fake cert into an image (default: legacy bypass_mode=1)
    Install {
        /// Input image file
        image: String,
        /// Output file (default <input>.signed)
        #[arg(short = 'o', long)]
        out: Option<String>,
        /// Use modern bypass (CVE-2025-20730): inject 0xA0 into root SEQUENCE
        #[arg(long)]
        modern: bool,
        /// Use legacy bypass (CVE-2023-20696): BIT STRING wrapper (default)
        #[arg(long)]
        legacy: bool,
    },
    /// Pack + install in one step (ready-to-flash)
    Build {
        /// Directory of edited chunks (indexed by filename prefix)
        dir: String,
        /// Original logo image as template
        template: String,
        /// Output file (default <template>.signed)
        #[arg(short = 'o', long)]
        out: Option<String>,
        /// Use modern bypass (default: legacy)
        #[arg(long)]
        modern: bool,
        /// Use legacy bypass (default)
        #[arg(long)]
        legacy: bool,
    },
    /// Verify fake cert is successfully installed and hashes match (auto-detect mode)
    Verify {
        /// Input image file
        image: String,
    },
}

fn resolve_mode(modern: bool, _legacy: bool) -> BypassMode {
    if modern {
        BypassMode::Modern
    } else {
        // default to legacy; --legacy is accepted but redundant
        BypassMode::Legacy
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            std::process::exit(2);
        }
    };

    match cmd {
        Commands::Unpack { image, out } => {
            logo_payload::unpack_logo(Path::new(&image), out.as_deref())?;
        }
        Commands::Pack { dir, template, out } => {
            let template_path = Path::new(&template);
            let packed = logo_payload::pack_logo(Path::new(&dir), template_path)?;
            let default_out = format!("{}.packed", template);
            let out_path = out.as_deref().unwrap_or(&default_out);
            std::fs::write(out_path, &packed)?;
            println!("[OK] written: {} ({} bytes)", out_path, packed.len());
            println!("Next: sign with  {} install {}", prog_name(), out_path);
        }
        Commands::Install { image, out, modern, legacy } => {
            let mode = resolve_mode(modern, legacy);
            let data = std::fs::read(&image)?;
            let signed = cert_inject::inject_fake_cert(&data, mode)?;
            let default_out = format!("{}.signed", image);
            let out_path = out.as_deref().unwrap_or(&default_out);
            std::fs::write(out_path, &signed)?;
            println!("[OK] written: {}", out_path);
        }
        Commands::Build { dir, template, out, modern, legacy } => {
            let mode = resolve_mode(modern, legacy);
            let packed = logo_payload::pack_logo(Path::new(&dir), Path::new(&template))?;
            println!();
            let signed = cert_inject::inject_fake_cert(&packed, mode)?;
            let default_out = format!("{}.signed", template);
            let out_path = out.as_deref().unwrap_or(&default_out);
            std::fs::write(out_path, &signed)?;
            println!("[OK] written: {} ({} bytes)", out_path, signed.len());
        }
        Commands::Verify { image } => {
            let data = std::fs::read(&image)?;
            let image_name = std::path::Path::new(&image)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or(image);
            cert_inject::verify_fake_cert(&data, &image_name)?;
        }
    }

    Ok(())
}