//! Tests for the Debian maintainer scripts.
//!
//! `postinst` runs as **root** on every `dpkg` configure, and it touches files inside
//! `/var/lib/npmfilter` — a directory the unprivileged `npmfilter` account owns. That makes
//! every path it names attacker-controlled the moment the daemon account is compromised: a
//! `chown`/`chmod` that follows a symlink hands that account root's ownership of any file on
//! the machine (`/etc/shadow` being the obvious target), on the next package upgrade.
//!
//! The state-tightening block is extracted from the real script — not copied here — and run
//! against a temporary directory, so these assertions are about the shipped code.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BEGIN: &str = "# --- BEGIN state-directory tightening";
const END: &str = "# --- END state-directory tightening ---";

fn postinst_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/debian/postinst")
}

/// The shipped tightening block, wired up to run against `home` as the current user.
fn tighten_script(home: &Path) -> String {
    let postinst = fs::read_to_string(postinst_path()).expect("the postinst is readable");
    let start = postinst
        .find(BEGIN)
        .expect("the postinst still marks its state-tightening block");
    let end = postinst
        .find(END)
        .expect("the postinst still marks the end of its state-tightening block");
    assert!(start < end, "the markers are the wrong way round");
    let body = &postinst[start..end];

    format!(
        "NPMFILTER_USER=$(id -un)\n\
         NPMFILTER_GROUP=$(id -gn)\n\
         NPMFILTER_HOME='{home}'\n\
         {body}\n\
         tighten_state_directory\n",
        home = home.display(),
    )
}

fn run_tighten(home: &Path) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(tighten_script(home))
        .output()
        .expect("sh runs");
    assert!(
        output.status.success(),
        "the tightening block failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn temp_home(tag: &str) -> PathBuf {
    let home =
        std::env::temp_dir().join(format!("npmfilter-postinst-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).expect("temp state home");
    home
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn write_with_mode(path: &Path, mode: u32) {
    fs::write(path, b"not really a database").expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

/// The reproduced attack: the daemon account owns its own state directory, so it replaces
/// `rules.db` with a link to a file it does not own and waits for the next upgrade. Root's
/// `chmod` used to follow the link and set the *target* to 0600.
#[test]
fn tightening_never_follows_a_symlink_out_of_the_state_directory() {
    let home = temp_home("symlink");
    let victim = home.join("victim.conf");
    write_with_mode(&victim, 0o644);

    for link in ["rules.db", "rules.db-wal", "rules.db-shm"] {
        let path = home.join(link);
        std::os::unix::fs::symlink(&victim, &path).expect("plant the symlink");
    }

    run_tighten(&home);

    assert_eq!(
        mode_of(&victim),
        0o644,
        "the mode of the symlink target must not have moved"
    );
    for link in ["rules.db", "rules.db-wal", "rules.db-shm"] {
        let path = home.join(link);
        assert!(
            fs::symlink_metadata(&path)
                .expect("stat the link")
                .file_type()
                .is_symlink(),
            "{link} must be left exactly as it was found"
        );
    }

    let _ = fs::remove_dir_all(&home);
}

/// A hard link is the same primitive without the `-L` test catching it.
#[test]
fn tightening_refuses_a_state_file_with_more_than_one_link() {
    let home = temp_home("hardlink");
    let victim = home.join("victim.conf");
    write_with_mode(&victim, 0o644);
    fs::hard_link(&victim, home.join("rules.db")).expect("plant the hard link");

    run_tighten(&home);

    assert_eq!(
        mode_of(&victim),
        0o644,
        "a shared inode must not be tightened through one of its names"
    );

    let _ = fs::remove_dir_all(&home);
}

/// And the thing it exists for still happens: a real, unshared state file left group-readable
/// by an older package is tightened.
#[test]
fn tightening_still_locks_down_a_real_state_file() {
    let home = temp_home("real");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o2775)).expect("loosen the home");
    write_with_mode(&home.join("rules.db"), 0o664);
    write_with_mode(&home.join("rules.db-wal"), 0o664);

    run_tighten(&home);

    assert_eq!(mode_of(&home), 0o700, "the state directory is owner-only");
    assert_eq!(mode_of(&home.join("rules.db")), 0o600);
    assert_eq!(mode_of(&home.join("rules.db-wal")), 0o600);

    let _ = fs::remove_dir_all(&home);
}

/// A state directory that is itself a symlink is refused outright rather than chmod-ed
/// through.
#[test]
fn a_symlinked_state_directory_is_refused() {
    let home = temp_home("dirlink");
    let real = home.join("real");
    fs::create_dir_all(&real).expect("target directory");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("chmod target");
    let link = home.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("plant the directory symlink");

    run_tighten(&link);

    assert_eq!(
        mode_of(&real),
        0o755,
        "the directory behind the link must not have been touched"
    );

    let _ = fs::remove_dir_all(&home);
}
