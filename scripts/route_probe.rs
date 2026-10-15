use plume_utils::{Package, PlistInfoTrait};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = PathBuf::from(env::args().nth(1).unwrap());
    let output = PathBuf::from(env::args().nth(2).unwrap());
    let package = Package::new(input.clone())?;
    let bundle = package.get_package_bundle()?;
    assert_eq!(bundle.get_bundle_identifier().as_deref(), Some("dev.zy6aa.signalprobe.tvos"));
    // Demonstrate the two public branches actually used by the CLI.
    let file_branch = package.get_archive_based_on_path(&input)?;
    assert_eq!(fs::read(&file_branch)?, fs::read(&input)?, "file branch should copy original bytes");
    let directory_branch = package.get_archive_based_on_path(bundle.bundle_dir())?;
    fs::copy(&directory_branch, &output)?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&output)?)?;
    let mut backslashes = 0;
    for i in 0..archive.len() {
        if archive.by_index(i)?.name().contains('\\') { backslashes += 1; }
    }
    println!("file_branch_preserves_original_bytes=true");
    println!("directory_roundtrip_backslash_entries={backslashes}");
    println!("directory_roundtrip_reparse_ok={}", Package::new(output).is_ok());
    package.remove_package_stage();
    Ok(())
}
