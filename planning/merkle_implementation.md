mavacs/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── hash.rs
│   ├── types.rs
│   ├── error.rs
│   │
│   ├── chronoforest/
│   │   ├── mod.rs
│   │   ├── arena.rs          # Node enum with Internal variant
│   │   ├── forest.rs
│   │   ├── digest.rs
│   │   ├── witness.rs
│   │   └── historical.rs
│   │
│   └── patricia/              # Future: PT lives inside Node::Internal
│       ├── mod.rs
│       ├── trie.rs
│       ├── node.rs
│       ├── prefix.rs
│       └── witness.rs