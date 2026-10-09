mod mkimg;
mod der;
mod image_io;
mod logo;
mod cert;

use std::path::Path;
use clap::{Parser, Subcommand};

const VERSION: &str = "1.4-dev";

/// MTK logo image toolchain: unpack / pack / install / build / verify
#[derive(Parser)]
#[command(name = "mtk-logo-toolkit", version = VERSION)]
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
    /// Inject legacy fake cert into an image (bypass_mode=1)
    Install {
        /// Input image file
        image: String,
        /// Output file (default <input>.signed)
        #[arg(short = 'o', long)]
        out: Option<String>,
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
    },
    /// Verify fake cert is successfully installed and hashes match
    Verify {
        /// Input image file
        image: String,
    },
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
            logo::unpack_image(Path::new(&image), out.as_deref())?;
        }
        Commands::Pack { dir, template, out } => {
            let template_path = Path::new(&template);
            let packed = logo::pack_image(Path::new(&dir), template_path)?;
            let default_out = format!("{}.packed", template);
            let out_path = out.as_deref().unwrap_or(&default_out);
            std::fs::write(out_path, &packed)?;
            println!("[OK] written: {} ({} bytes)", out_path, packed.len());
            println!("Next: sign with  mtk-logo-toolkit install {}", out_path);
        }
        Commands::Install { image, out } => {
            let data = std::fs::read(&image)?;
            let signed = cert::install_image(&data)?;
            let default_out = format!("{}.signed", image);
            let out_path = out.as_deref().unwrap_or(&default_out);
            std::fs::write(out_path, &signed)?;
            println!("[OK] written: {}", out_path);
        }
        Commands::Build { dir, template, out } => {
            let packed = logo::pack_image(Path::new(&dir), Path::new(&template))?;
            println!();
            let signed = cert::install_image(&packed)?;
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
            cert::verify_image(&data, &image_name)?;
        }
    }

    Ok(())
}
