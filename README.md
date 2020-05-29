# LsRules

[Little Snitch][little_snitch] is like an application based firewall.  It allows
a user to control what connections can be made to and from local applications.
You can choose to allow or deny connections based on a set of rules (such as the
domain or hostname being connected to, the ports used, the application receiving
or making the connection, etc.).

[LsRules][lsrules] is a file format which specifies rules which Little Snitch
can use. This library is a [Serde][serde] model for serializing and
deserializing `.lsrules` files.

## Installation

```toml
[dependencies]
ls_rules = "0.1.0"
```

## License

Licensed under either of [Apache License, Version 2.0][LICENSE_APACHE] or [MIT
License][LICENSE_MIT] at your option.

### Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[LICENSE_APACHE]: LICENSE-APACHE
[LICENSE_MIT]: LICENSE-MIT
[little_snitch]: https://www.obdev.at/products/littlesnitch/index.html
[lsrules]: https://help.obdev.at/littlesnitch/ref-lsrules-file-format
[serde]: https://serde.rs
