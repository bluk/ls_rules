// Copyright 2022 Bryant Luk
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # Little Snitch Rules
//!
//! [Little Snitch][little_snitch] is like an application based firewall.  It allows
//! a user to control what connections can be made to and from local applications.
//! You can choose to allow or deny connections based on a set of rules (such as the
//! domain or hostname being connected to, the ports used, the application receiving
//! or making the connection, etc.).
//!
//! [.lsrules][lsrules] is a file format which specifies rules which Little Snitch
//! can use. This library is a [Serde][serde] model for serializing and
//! deserializing `.lsrules` files.
//!
//! [little_snitch]: https://www.obdev.at/products/littlesnitch/index.html
//! [lsrules]: https://help.obdev.at/littlesnitch/ref-lsrules-file-format
//! [serde]: https://serde.rs

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// The container for all data.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LsRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<Rule>>,
    #[serde(
        rename = "denied-remote-domains",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_domains: Option<Vec<String>>,
    #[serde(
        rename = "denied-remote-hosts",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_hosts: Option<Vec<String>>,
    #[serde(
        rename = "denied-remote-addresses",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_addresses: Option<Vec<String>>,
    #[serde(
        rename = "denied-remote-notes",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_notes: Option<String>,
}

/// A specific rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Rule {
    pub process: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "remote-addresses", skip_serializing_if = "Option::is_none")]
    pub remote_addresses: Option<String>,
    #[serde(rename = "remote-hosts", skip_serializing_if = "Option::is_none")]
    pub remote_hosts: Option<RemoteHosts>,
    #[serde(rename = "remote-domains", skip_serializing_if = "Option::is_none")]
    pub remote_domains: Option<RemoteDomains>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<Remote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Ports>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RemoteHosts {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RemoteDomains {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Remote {
    Any,
    LocalNet,
    Multicast,
    Broadcast,
    Bonjour,
    DnsServers,
    Bpf,
    Unknown(String),
}

impl Serialize for Remote {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Remote::Any => serializer.serialize_str("any"),
            Remote::LocalNet => serializer.serialize_str("local-net"),
            Remote::Multicast => serializer.serialize_str("multicast"),
            Remote::Broadcast => serializer.serialize_str("broadcast"),
            Remote::Bonjour => serializer.serialize_str("bonjour"),
            Remote::DnsServers => serializer.serialize_str("dns-servers"),
            Remote::Bpf => serializer.serialize_str("bpf"),
            Remote::Unknown(s) => serializer.serialize_str(s),
        }
    }
}

struct RemoteVisitor;

impl<'de> Visitor<'de> for RemoteVisitor {
    type Value = Remote;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "any" => Ok(Remote::Any),
            "local-net" => Ok(Remote::LocalNet),
            "multicast" => Ok(Remote::Multicast),
            "broadcast" => Ok(Remote::Broadcast),
            "bonjour" => Ok(Remote::Bonjour),
            "dns-servers" => Ok(Remote::DnsServers),
            "bpf" => Ok(Remote::Bpf),
            _ => Ok(Remote::Unknown(String::from(v))),
        }
    }
}

impl<'de> Deserialize<'de> for Remote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(RemoteVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Direction {
    Incoming,
    Outgoing,
    Unknown(String),
}

impl Default for Direction {
    fn default() -> Self {
        Direction::Outgoing
    }
}

impl Serialize for Direction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Direction::Incoming => serializer.serialize_str("incoming"),
            Direction::Outgoing => serializer.serialize_str("outgoing"),
            Direction::Unknown(s) => serializer.serialize_str(s),
        }
    }
}

struct DirectionVisitor;

impl<'de> Visitor<'de> for DirectionVisitor {
    type Value = Direction;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "incoming" => Ok(Direction::Incoming),
            "outgoing" => Ok(Direction::Outgoing),
            _ => Ok(Direction::Unknown(String::from(v))),
        }
    }
}

impl<'de> Deserialize<'de> for Direction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DirectionVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Action {
    Allow,
    Deny,
    Ask,
    Unknown(String),
}

impl Default for Action {
    fn default() -> Self {
        Action::Ask
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Action::Allow => serializer.serialize_str("allow"),
            Action::Deny => serializer.serialize_str("deny"),
            Action::Ask => serializer.serialize_str("ask"),
            Action::Unknown(s) => serializer.serialize_str(s),
        }
    }
}

struct ActionVisitor;

impl<'de> Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            "ask" => Ok(Action::Ask),
            _ => Ok(Action::Unknown(String::from(v))),
        }
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Priority {
    Default,
    High,
    Unknown(String),
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Default
    }
}

impl Serialize for Priority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Priority::Default => serializer.serialize_str("default"),
            Priority::High => serializer.serialize_str("high"),
            Priority::Unknown(s) => serializer.serialize_str(s),
        }
    }
}

struct PriorityVisitor;

impl<'de> Visitor<'de> for PriorityVisitor {
    type Value = Priority;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "default" => Ok(Priority::Default),
            "high" => Ok(Priority::High),
            _ => Ok(Priority::Unknown(String::from(v))),
        }
    }
}

impl<'de> Deserialize<'de> for Priority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PriorityVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Ports {
    Any,
    Single(u16),
    Range(u16, u16),
    Unknown(String),
}

impl Default for Ports {
    fn default() -> Self {
        Ports::Any
    }
}

impl Serialize for Ports {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Ports::Any => serializer.serialize_str("any"),
            Ports::Single(p) => serializer.serialize_str(&p.to_string()),
            Ports::Range(p1, p2) => {
                serializer.serialize_str(&format!("{}-{}", &p1.to_string(), &p2.to_string()))
            }
            Ports::Unknown(s) => serializer.serialize_str(s),
        }
    }
}

struct PortsVisitor;

impl<'de> Visitor<'de> for PortsVisitor {
    type Value = Ports;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string, integer, or range value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if matches!(&v.to_lowercase()[..], "any") {
            return Ok(Ports::Any);
        }

        if let Ok(v) = u16::from_str(v) {
            return Ok(Ports::Single(v));
        }

        let ports: Vec<&str> = v.split('-').collect();
        if ports.len() == 2 {
            if let Ok(p1) = u16::from_str(ports[0]) {
                if let Ok(p2) = u16::from_str(ports[1]) {
                    return Ok(Ports::Range(p1, p2));
                }
            }
        }

        Ok(Ports::Unknown(String::from(v)))
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PortsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules() {
        let rules: LsRules = LsRules::default();
        assert_eq!(rules.name, None);
        assert_eq!(rules.description, None);
        assert_eq!(rules.rules, None);
        assert_eq!(rules.denied_remote_domains, None);
        assert_eq!(rules.denied_remote_hosts, None);
        assert_eq!(rules.denied_remote_addresses, None);
        assert_eq!(rules.denied_remote_notes, None);
    }

    #[test]
    fn test_empty_rules() -> Result<(), serde_json::Error> {
        let json = r#"
{
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        assert_eq!(rules.name, None);
        assert_eq!(rules.description, None);
        Ok(())
    }

    #[test]
    fn test_metadata() -> Result<(), serde_json::Error> {
        let json = r#"
{
    "name": "Social Media Block List",
    "description": "Blocks access to popular social media sites."
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some(String::from("Social Media Block List")));
        assert_eq!(
            rules.description,
            Some(String::from("Blocks access to popular social media sites."))
        );
        Ok(())
    }

    #[test]
    fn test_denied_remote_domains() -> Result<(), serde_json::Error> {
        let json = r#"
{
    "name": "Social Media Block List",
    "description": "Blocks access to popular social media sites.",
    "denied-remote-domains": ["facebook.com", "twitter.com", "youtube.com"]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some(String::from("Social Media Block List")));
        assert_eq!(
            rules.description,
            Some(String::from("Blocks access to popular social media sites."))
        );
        assert_eq!(
            rules.denied_remote_domains,
            Some(vec![
                String::from("facebook.com"),
                String::from("twitter.com"),
                String::from("youtube.com")
            ])
        );
        Ok(())
    }

    #[test]
    fn test_basic_rule() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "name": "LaunchBar Software Update",
  "description": "This rule allows LaunchBar to check for updates.",
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar",
      "remote-hosts": "sw-update.obdev.at"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some(String::from("LaunchBar Software Update")));
        assert_eq!(
            rules.description,
            Some(String::from(
                "This rule allows LaunchBar to check for updates."
            ))
        );

        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            String::from("/Applications/LaunchBar.app/Contents/MacOS/LaunchBar")
        );
        assert_eq!(
            rule.remote_hosts,
            Some(RemoteHosts::Single(String::from("sw-update.obdev.at")))
        );
        Ok(())
    }

    #[test]
    fn test_multiple_hosts() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "name": "LaunchBar Software Update",
  "description": "This rule allows LaunchBar to check for updates.",
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar",
      "remote-hosts": ["sw-update.obdev.at", "example.com"]
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some(String::from("LaunchBar Software Update")));
        assert_eq!(
            rules.description,
            Some(String::from(
                "This rule allows LaunchBar to check for updates."
            ))
        );

        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            String::from("/Applications/LaunchBar.app/Contents/MacOS/LaunchBar")
        );
        assert_eq!(
            rule.remote_hosts,
            Some(RemoteHosts::Multiple(vec![
                String::from("sw-update.obdev.at"),
                String::from("example.com")
            ]))
        );
        Ok(())
    }

    #[test]
    fn test_remote_enum_any() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar",
      "remote": "any"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            String::from("/Applications/LaunchBar.app/Contents/MacOS/LaunchBar")
        );
        assert_eq!(rule.remote, Some(Remote::Any));
        Ok(())
    }

    #[test]
    fn test_remote_enum_local_net() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar",
      "remote": "local-net"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            String::from("/Applications/LaunchBar.app/Contents/MacOS/LaunchBar")
        );
        assert_eq!(rule.remote, Some(Remote::LocalNet));
        Ok(())
    }

    #[test]
    fn test_remote_enum_unknown() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar",
      "remote": "my-custom"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            String::from("/Applications/LaunchBar.app/Contents/MacOS/LaunchBar")
        );
        assert_eq!(
            rule.remote,
            Some(Remote::Unknown(String::from("my-custom")))
        );
        Ok(())
    }

    #[test]
    fn test_ports_any() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/Safari.app/Contents/MacOS/Safari",
      "remote": "any",
      "ports": "any"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.ports, Some(Ports::Any));
        Ok(())
    }

    #[test]
    fn test_ports_single() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/Safari.app/Contents/MacOS/Safari",
      "remote": "any",
      "ports": "443"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.ports, Some(Ports::Single(443)));
        Ok(())
    }

    #[test]
    fn test_ports_range() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/Safari.app/Contents/MacOS/Safari",
      "remote": "any",
      "ports": "80-443"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.ports, Some(Ports::Range(80, 443)));
        Ok(())
    }

    #[test]
    fn test_ports_custom() -> Result<(), serde_json::Error> {
        let json = r#"
{
  "rules": [
    {
      "action": "allow",
      "process": "/Applications/Safari.app/Contents/MacOS/Safari",
      "remote": "any",
      "ports": "my-custom"
    }
  ]
}
"#;
        let rules: LsRules = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.ports, Some(Ports::Unknown(String::from("my-custom"))));
        Ok(())
    }
}
