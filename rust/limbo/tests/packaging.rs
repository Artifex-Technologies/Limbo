//! The PKGBUILD advertises the runtime packages as optdepends so Limbo can ship without them (internal/deps's
//! packaging test, carried over when the Go code left): if `limbo setup` gains a package the PKGBUILD does not mention,
//! setup would install something the package never told anyone about. And none of them is a hard dependency.

#[test]
fn pkgbuild_optdepends_cover_every_required_package() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/arch");
    let text = std::fs::read_to_string(format!("{dir}/PKGBUILD")).unwrap();
    let start = text.find("\noptdepends=(").expect("no optdepends block in the PKGBUILD");
    let block = &text[start..start + text[start..].find("\n)").expect("the optdepends block ends")];
    let depends = text.lines().find(|l| l.starts_with("depends=(")).expect("no depends line in the PKGBUILD");
    for (cmd, pkg, _) in limbo::cli::setup::REQUIRED {
        assert!(block.contains(&format!("'{pkg}:")), "package {pkg:?} (needed for {cmd}) is missing from the PKGBUILD's optdepends");
        assert!(!depends.contains(&format!("'{pkg}'")), "{pkg:?} is a hard dependency; Limbo is meant to ship without its runtime");
    }
    assert!(std::path::Path::new(&format!("{dir}/limbo.install")).exists(), "the PKGBUILD references limbo.install");
    // the Go build is gone from the package: nothing builds or installs it
    assert!(
        !text.contains("$pkgdir/usr/lib/limbo/limbo-go")
            && !text.lines().any(|l| l.trim_start().starts_with("go "))
            && !text.contains("'go'"),
        "the PKGBUILD still builds or installs the Go limbo"
    );
}
