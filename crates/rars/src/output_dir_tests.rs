use super::*;

fn mode(overwrite: OverwritePolicy) -> DirMode {
    DirMode {
        overwrite,
        in_place: false,
        restore_times: false,
        flatten: false,
        exists_hint: "",
    }
}

fn file(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
}

fn dir(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, true)
}

fn write(outputs: &mut DirOutputs<'_>, meta: &crate::ExtractedEntryMeta, bytes: &[u8]) {
    let mut writer = outputs.open_settled(meta).unwrap();
    writer.write_all(bytes).unwrap();
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn settling_publishes_verified_members_and_drops_failed_ones() {
    let root = crate::scratch::case("dir-outputs-settled");
    let mut outputs = DirOutputs::new(
        &root,
        crate::ArchiveFamily::Rar50Plus,
        None,
        mode(OverwritePolicy::Never),
        None,
    );
    write(&mut outputs, &file("kept"), b"kept");
    write(&mut outputs, &file("broken"), b"broken");
    write(&mut outputs, &file("later"), b"later");
    assert!(
        !root.join("kept").exists(),
        "nothing is published before it settles"
    );
    outputs.settle(true).unwrap();
    outputs.settle(false).unwrap();
    outputs.settle(true).unwrap();
    let extracted = outputs.finish(Ok(())).unwrap();
    assert_eq!(listing(&root), ["kept", "later"]);
    assert_eq!(fs::read(root.join("kept")).unwrap(), b"kept");
    assert_eq!(extracted.paths, [root.join("kept"), root.join("later")]);
}

#[test]
fn a_member_on_the_path_of_an_unsettled_one_is_refused_only_once_that_one_publishes() {
    for first_verified in [true, false] {
        let root = crate::scratch::case("dir-outputs-settled-same-path");
        let mut outputs = DirOutputs::new(
            &root,
            crate::ArchiveFamily::Rar50Plus,
            None,
            mode(OverwritePolicy::Never),
            None,
        );
        write(&mut outputs, &file("same"), b"first");
        write(&mut outputs, &file("same"), b"second");
        outputs.settle(first_verified).unwrap();
        let second = outputs.settle(true);
        let extracted = outputs.finish(Ok(())).unwrap();
        if first_verified {
            let error = second.unwrap_err().to_string();
            assert!(error.contains("already exists"), "{error}");
            assert_eq!(fs::read(root.join("same")).unwrap(), b"first");
        } else {
            second.unwrap();
            assert_eq!(fs::read(root.join("same")).unwrap(), b"second");
        }
        assert_eq!(extracted.paths, [root.join("same")]);
        assert_eq!(listing(&root), ["same"]);
    }
}

#[test]
fn a_directory_is_made_once_the_members_before_it_settle() {
    let root = crate::scratch::case("dir-outputs-settled-directory");
    let mut outputs = DirOutputs::new(
        &root,
        crate::ArchiveFamily::Rar50Plus,
        None,
        mode(OverwritePolicy::Always),
        None,
    );
    write(&mut outputs, &file("taken"), b"file");
    outputs.open_settled(&dir("taken")).unwrap();
    outputs.settle(true).unwrap();
    let error = outputs.settle(true).unwrap_err();
    outputs.finish(Ok(())).unwrap();
    assert!(
        matches!(&error, crate::Error::Io(error) if error.kind == io::ErrorKind::AlreadyExists),
        "{error}"
    );
    assert_eq!(fs::read(root.join("taken")).unwrap(), b"file");
}

#[test]
fn a_file_on_the_path_of_an_unsettled_directory_is_refused_as_already_there() {
    let root = crate::scratch::case("dir-outputs-settled-file-on-directory");
    let mut outputs = DirOutputs::new(
        &root,
        crate::ArchiveFamily::Rar50Plus,
        None,
        mode(OverwritePolicy::Never),
        None,
    );
    outputs.open_settled(&dir("taken")).unwrap();
    write(&mut outputs, &file("taken"), b"file");
    outputs.settle(true).unwrap();
    let error = outputs.settle(true).unwrap_err().to_string();
    outputs.finish(Ok(())).unwrap();
    assert!(error.contains("taken already exists"), "{error}");
    assert!(root.join("taken").is_dir());
}
