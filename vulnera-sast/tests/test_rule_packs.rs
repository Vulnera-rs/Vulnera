use std::fs;
use std::path::PathBuf;

use git2::{Repository, Signature};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use vulnera_core::config::RulePackConfig;
use vulnera_sast::infrastructure::rules::{RuleLoader, RulePackLoader};

fn write_rule_pack(repo_path: &PathBuf, content: &str) -> PathBuf {
    let rules_path = repo_path.join("rules.toml");
    fs::write(&rules_path, content).expect("write rules file");
    rules_path
}

fn commit_all(repo: &Repository, message: &str) {
    let mut index = repo.index().expect("index");
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .expect("add files");
    index.write().expect("write index");

    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("tree");
    let sig = Signature::now("tester", "tester@example.com").expect("signature");

    let parent_commit = repo
        .head()
        .ok()
        .and_then(|h| h.target())
        .and_then(|oid| repo.find_commit(oid).ok());

    let parent_refs: Vec<&git2::Commit> =
        parent_commit.as_ref().map(|c| vec![c]).unwrap_or_default();

    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .expect("commit");
}

#[test]
fn test_rule_pack_loader_loads_rules_from_git() {
    let repo_dir = TempDir::new().expect("temp repo");
    let repo = Repository::init(repo_dir.path()).expect("init repo");

    let rules_content = r#"
[[rules]]
id = "pack-rule"
name = "Pack Rule"
description = "From pack"
severity = "High"
languages = ["Python"]
pattern = { type = "TreeSitterQuery", value = "(identifier) @name" }
"#;

    let _rules_path = write_rule_pack(&repo_dir.path().to_path_buf(), rules_content);
    commit_all(&repo, "add rules");

    let mut hasher = Sha256::new();
    hasher.update(rules_content.as_bytes());
    let checksum = hex::encode(hasher.finalize());

    let pack = RulePackConfig {
        name: "local-pack".to_string(),
        git_url: repo_dir.path().to_string_lossy().to_string(),
        reference: Some("HEAD".to_string()),
        rules_path: PathBuf::from("rules.toml"),
        checksum_sha256: Some(checksum),
        enabled: true,
    };

    let loader = RulePackLoader::new(vec![pack], vec![]);
    let rules = loader.load_rules().expect("load rules");

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "pack-rule");
    assert_eq!(rules[0].name, "Pack Rule");
}
