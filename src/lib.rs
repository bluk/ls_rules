// Copyright 2022 Bryant Luk
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

use core::{fmt, str::FromStr};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{format, string::ToString, vec::Vec};
#[cfg(feature = "std")]
use std::{format, string::ToString, vec::Vec};

use serde::{de::Visitor, Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};

/// The container for all data.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LsRules<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<Rule<'a>>>,
    #[serde(
        rename = "denied-remote-domains",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_domains: Option<Vec<&'a str>>,
    #[serde(
        rename = "denied-remote-hosts",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_hosts: Option<Vec<&'a str>>,
    #[serde(
        rename = "denied-remote-addresses",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_addresses: Option<Vec<&'a str>>,
    #[serde(
        rename = "denied-remote-notes",
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_remote_notes: Option<&'a str>,
}

/// A specific rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Rule<'a> {
    pub process: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<&'a str>,
    #[serde(rename = "remote-addresses", skip_serializing_if = "Option::is_none")]
    pub remote_addresses: Option<&'a str>,
    #[serde(rename = "remote-hosts", skip_serializing_if = "Option::is_none")]
    pub remote_hosts: Option<RemoteHosts<'a>>,
    #[serde(rename = "remote-domains", skip_serializing_if = "Option::is_none")]
    pub remote_domains: Option<RemoteDomains<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", borrow)]
    pub remote: Option<Remote<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Ports<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RemoteHosts<'a> {
    Single(&'a str),
    Multiple(Vec<&'a str>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RemoteDomains<'a> {
    Single(&'a str),
    Multiple(Vec<&'a str>),
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Remote<'a> {
    Any,
    LocalNet,
    Multicast,
    Broadcast,
    Bonjour,
    DnsServers,
    Bpf,
    Unknown(&'a str),
}

impl<'a> serde::Serialize for Remote<'a> {
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
    type Value = Remote<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
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
            _ => Ok(Remote::Unknown(v)),
        }
    }
}

impl<'de, 'a> serde::Deserialize<'de> for Remote<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(RemoteVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Direction<'a> {
    Incoming,
    Outgoing,
    Unknown(&'a str),
}

impl<'a> Default for Direction<'a> {
    fn default() -> Self {
        Direction::Outgoing
    }
}

impl<'a> serde::Serialize for Direction<'a> {
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
    type Value = Direction<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "incoming" => Ok(Direction::Incoming),
            "outgoing" => Ok(Direction::Outgoing),
            _ => Ok(Direction::Unknown(v)),
        }
    }
}

impl<'de, 'a> serde::Deserialize<'de> for Direction<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DirectionVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Action<'a> {
    Allow,
    Deny,
    Ask,
    Unknown(&'a str),
}

impl<'a> Default for Action<'a> {
    fn default() -> Self {
        Action::Ask
    }
}

impl<'a> serde::Serialize for Action<'a> {
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
    type Value = Action<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            "ask" => Ok(Action::Ask),
            _ => Ok(Action::Unknown(v)),
        }
    }
}

impl<'de, 'a> serde::Deserialize<'de> for Action<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Priority<'a> {
    Default,
    High,
    Unknown(&'a str),
}

impl<'a> Default for Priority<'a> {
    fn default() -> Self {
        Priority::Default
    }
}

impl<'a> serde::Serialize for Priority<'a> {
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
    type Value = Priority<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match &v.to_lowercase()[..] {
            "default" => Ok(Priority::Default),
            "high" => Ok(Priority::High),
            _ => Ok(Priority::Unknown(v)),
        }
    }
}

impl<'de, 'a> serde::Deserialize<'de> for Priority<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PriorityVisitor)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Ports<'a> {
    Any,
    Single(u16),
    Range(u16, u16),
    Unknown(&'a str),
}

impl<'a> Default for Ports<'a> {
    fn default() -> Self {
        Ports::Any
    }
}

impl<'a> serde::Serialize for Ports<'a> {
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
    type Value = Ports<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string, integer, or range value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
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

        Ok(Ports::Unknown(v))
    }
}

impl<'de, 'a> serde::Deserialize<'de> for Ports<'a>
where
    'de: 'a,
{
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

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    use alloc::vec;

    #[test]
    fn test_default_rules() {
        let rules: LsRules<'_> = LsRules::default();
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
        let json = r"
{
}
";
        let rules: LsRules<'_> = serde_json::from_str(json)?;
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some("Social Media Block List"));
        assert_eq!(
            rules.description,
            Some("Blocks access to popular social media sites.")
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some("Social Media Block List"));
        assert_eq!(
            rules.description,
            Some("Blocks access to popular social media sites.")
        );
        assert_eq!(
            rules.denied_remote_domains,
            Some(vec!["facebook.com", "twitter.com", "youtube.com"])
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some("LaunchBar Software Update"));
        assert_eq!(
            rules.description,
            Some("This rule allows LaunchBar to check for updates.")
        );

        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar"
        );
        assert_eq!(
            rule.remote_hosts,
            Some(RemoteHosts::Single("sw-update.obdev.at"))
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        assert_eq!(rules.name, Some("LaunchBar Software Update"));
        assert_eq!(
            rules.description,
            Some("This rule allows LaunchBar to check for updates.")
        );

        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar"
        );
        assert_eq!(
            rule.remote_hosts,
            Some(RemoteHosts::Multiple(vec![
                "sw-update.obdev.at",
                "example.com"
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar"
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar"
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.action, Some(Action::Allow));
        assert_eq!(
            rule.process,
            "/Applications/LaunchBar.app/Contents/MacOS/LaunchBar"
        );
        assert_eq!(rule.remote, Some(Remote::Unknown("my-custom")));
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
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
        let rules: LsRules<'_> = serde_json::from_str(json)?;
        let rules = rules.rules.expect("expecting rules");
        assert_eq!(rules.len(), 1);
        let rule = rules.first().expect("first rule to exist");
        assert_eq!(rule.ports, Some(Ports::Unknown("my-custom")));
        Ok(())
    }
}
