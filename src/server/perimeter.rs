/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
//! Security perimeters: which sets of routes answer which networks.
//!
//! Two files say it, because two different people know the two halves.
//!
//! **The flavour** knows which of its routes are public and which are not,
//! and says so in `internals.js`, naming networks by role:
//!
//! ```text
//! "perimeter_route": {                    // in key order, first match wins
//!   "1": "/public/signup:anywhere",
//!   "2": "/admin/*:internal",
//!   "9": "*:internal"
//! }
//! ```
//!
//! **The installation** knows what `internal` is on this host — its private
//! networks, its proxies — and whether the perimeter is on at all, and says
//! so in `features.js`, the file core never writes and nothing over HTTP can
//! change:
//!
//! ```text
//! "perimeter": {
//!   "mode": "report",                     // or "enforce"
//!   "networks": { "internal": ["198.51.100.0/24", "!198.51.100.1/32"] },
//!   "trusted_proxies": ["127.0.0.1/32", "198.51.100.1/32"]
//! }
//! ```
//!
//! `anywhere` (every address) is built in. Without a `perimeter` feature
//! there is no perimeter, whatever the flavour declares — a development
//! install is not locked out of itself. With one, a request is let through
//! when the client's address is in the network its route names, and a route
//! no rule names is refused: what the flavour forgot to list is closed.
//!
//! **The client's address.** Behind proxies the connection comes from the
//! last proxy, and the client is named in `X-Forwarded-For`. That header is
//! anyone's to write, so it is read from the right and only through the
//! proxies listed as trusted: starting at the connection's peer, while the
//! address in hand is a trusted proxy, step one entry to the left. The first
//! address that is not a trusted proxy is the client. A forged entry sits to
//! the left of what the real proxies appended and is never reached.
//!
//! **Report mode** logs every request that would be refused and lets it
//! through, so a perimeter can be switched on, watched, and only then
//! enforced — without locking out the people it was meant to admit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpResponse};
use isabelle_dm::data_model::item::Item;
use log::{info, warn};

use crate::state::state::State;

/// An address block: `198.51.100.0/24`, `::1/128`, or a bare address.
#[derive(Debug, Clone, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// An IPv4 address carried in IPv6 (`::ffff:a.b.c.d`) is that IPv4 address:
/// a dual-stack socket reports v4 peers that way.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Cidr> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (text, None),
        };
        let addr = canonical(addr.parse::<IpAddr>().ok()?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix as u32)
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix as u32)
                };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// A named network: blocks it takes in, minus blocks it leaves out.
#[derive(Debug, Clone, Default)]
pub struct Network {
    include: Vec<Cidr>,
    exclude: Vec<Cidr>,
}

impl Network {
    /// Entries such as `192.0.2.0/24`, `127.0.0.1`, `!192.0.2.1`, as a JSON
    /// list or one comma-separated string. An entry that does not parse is
    /// dropped and logged: a typo must not widen a network, and dropping an
    /// include can only narrow it.
    pub fn parse(name: &str, spec: &serde_json::Value) -> Network {
        let entries: Vec<String> = match spec {
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            serde_json::Value::String(s) => s.split(',').map(str::to_string).collect(),
            _ => Vec::new(),
        };
        let mut n = Network::default();
        for part in entries.iter().filter(|p| !p.trim().is_empty()) {
            let (neg, text) = match part.trim().strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, part.trim()),
            };
            match Cidr::parse(text) {
                Some(c) if neg => n.exclude.push(c),
                Some(c) => n.include.push(c),
                None => warn!("perimeter: network {}: ignoring {:?}", name, part.trim()),
            }
        }
        n
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.include.iter().any(|c| c.contains(ip)) && !self.exclude.iter().any(|c| c.contains(ip))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Mode {
    /// No perimeter declared.
    #[default]
    Off,
    /// Log what would be refused; refuse nothing.
    Report,
    Enforce,
}

#[derive(Debug, Clone, PartialEq)]
enum Pattern {
    Any,
    Prefix(String),
    Exact(String),
}

impl Pattern {
    fn parse(text: &str) -> Pattern {
        match text.trim() {
            "*" => Pattern::Any,
            t if t.ends_with('*') => Pattern::Prefix(t.trim_end_matches('*').to_string()),
            t => Pattern::Exact(t.to_string()),
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Pattern::Any => true,
            Pattern::Prefix(p) => path.starts_with(p.as_str()),
            Pattern::Exact(p) => path == p,
        }
    }
}

/// The perimeter as declared, parsed once with the route cache.
#[derive(Debug, Clone, Default)]
pub struct Perimeter {
    pub mode: Mode,
    proxies: Vec<Cidr>,
    networks: HashMap<String, Network>,
    rules: Vec<(Pattern, String)>,
}

/// What the perimeter says about one request.
#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub allowed: bool,
    /// The network the route needed; `None` when no rule named the route.
    pub network: Option<String>,
}

impl Perimeter {
    /// The perimeter from the flavour's routes and the installation's
    /// `perimeter` feature. No feature, no perimeter.
    pub fn from_config(internals: &Item, deployment: Option<&serde_json::Value>) -> Perimeter {
        let empty = HashMap::new();
        let mut rules: Vec<(u64, Pattern, String)> = internals
            .strstrs
            .get("perimeter_route")
            .unwrap_or(&empty)
            .iter()
            .filter_map(|(k, spec)| {
                let (pattern, net) = spec.rsplit_once(':')?;
                Some((
                    k.parse::<u64>().unwrap_or(u64::MAX),
                    Pattern::parse(pattern),
                    net.trim().to_string(),
                ))
            })
            .collect();
        rules.sort_by_key(|(k, _, _)| *k);

        let Some(dep) = deployment else {
            if !rules.is_empty() {
                info!(
                    "perimeter: the flavour declares {} route rule(s); off, as features.js has no perimeter",
                    rules.len()
                );
            }
            return Perimeter::default();
        };
        if rules.is_empty() {
            warn!("perimeter: features.js turns it on, but internals.js declares no perimeter_route; off");
            return Perimeter::default();
        }

        let mut networks: HashMap<String, Network> = HashMap::new();
        networks.insert(
            "anywhere".to_string(),
            Network::parse("anywhere", &serde_json::json!(["0.0.0.0/0", "::/0"])),
        );
        if let Some(map) = dep["networks"].as_object() {
            for (name, spec) in map {
                networks.insert(name.clone(), Network::parse(name, spec));
            }
        }
        for (_, _, net) in &rules {
            if !networks.contains_key(net) {
                warn!(
                    "perimeter: a rule names network {:?}, which features.js does not define — it admits nobody",
                    net
                );
            }
        }
        let proxies = Network::parse("trusted_proxies", &dep["trusted_proxies"]).include;
        let mode = match dep["mode"].as_str().unwrap_or("enforce") {
            "report" => Mode::Report,
            "off" => Mode::Off,
            _ => Mode::Enforce,
        };
        Perimeter {
            mode,
            proxies,
            networks,
            rules: rules.into_iter().map(|(_, p, n)| (p, n)).collect(),
        }
    }

    fn trusted(&self, ip: IpAddr) -> bool {
        self.proxies.iter().any(|c| c.contains(ip))
    }

    /// The client's address, from the connection's peer and
    /// `X-Forwarded-For`, through trusted proxies only.
    pub fn client(&self, peer: Option<IpAddr>, forwarded_for: &[&str]) -> Option<IpAddr> {
        let mut current = canonical(peer?);
        let chain: Vec<IpAddr> = forwarded_for
            .iter()
            .flat_map(|h| h.split(','))
            .filter_map(parse_forwarded_addr)
            .collect();
        let mut left = chain.len();
        while self.trusted(current) && left > 0 {
            left -= 1;
            current = chain[left];
        }
        Some(current)
    }

    pub fn decide(&self, path: &str, client: Option<IpAddr>) -> Verdict {
        let Some((_, net)) = self.rules.iter().find(|(p, _)| p.matches(path)) else {
            return Verdict {
                allowed: false,
                network: None,
            };
        };
        let allowed = match (client, self.networks.get(net)) {
            (Some(ip), Some(n)) => n.contains(ip),
            _ => false,
        };
        Verdict {
            allowed,
            network: Some(net.clone()),
        }
    }
}

/// One entry of `X-Forwarded-For`: an address, perhaps with a port, perhaps
/// an IPv6 one in brackets. Anything else (`unknown`, an obfuscated name)
/// is not an address and is skipped.
fn parse_forwarded_addr(entry: &str) -> Option<IpAddr> {
    let e = entry.trim().trim_matches('"');
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    if let Some(rest) = e.strip_prefix('[') {
        return rest
            .split(']')
            .next()?
            .parse::<Ipv6Addr>()
            .ok()
            .map(IpAddr::V6);
    }
    let (host, port) = e.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// The middleware. Outermost of the guards: a request from outside the
/// network its route needs gets no further — not to the session, not to a
/// token check, not to a plugin.
pub async fn enforce_perimeter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let perimeter = req
        .app_data::<actix_web::web::Data<State>>()
        .map(|s| s.server.route_cache.lock().perimeter.clone());
    let Some(perimeter) = perimeter.filter(|p| p.mode != Mode::Off) else {
        return next.call(req).await.map(|r| r.map_into_left_body());
    };

    let forwarded: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .filter_map(|v| v.to_str().ok())
        .collect();
    let client = perimeter.client(req.peer_addr().map(|a| a.ip()), &forwarded);
    let path = req.path().to_string();
    let verdict = perimeter.decide(&path, client);
    if verdict.allowed {
        return next.call(req).await.map(|r| r.map_into_left_body());
    }

    let who = client
        .map(|c| c.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let needs = verdict.network.as_deref().unwrap_or("(no rule)");
    if perimeter.mode == Mode::Report {
        info!(
            "perimeter (report only): would refuse {} {} from {}, which needs {}",
            req.method(),
            path,
            who,
            needs
        );
        return next.call(req).await.map(|r| r.map_into_left_body());
    }
    warn!(
        "perimeter: refused {} {} from {}, which needs {}",
        req.method(),
        path,
        who,
        needs
    );
    let body = serde_json::json!({
        "succeeded": false,
        "error": "This service is not reachable from your network.",
    })
    .to_string();
    Ok(req
        .into_response(
            HttpResponse::Forbidden()
                .content_type("application/json")
                .body(body),
        )
        .map_into_right_body())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn internals() -> Item {
        let mut i = Item::new();
        let rules: HashMap<String, String> = [
            ("1", "/public/signup:anywhere"),
            ("2", "/public/status:anywhere"),
            ("10", "*:internal"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        i.strstrs.insert("perimeter_route".into(), rules);
        i
    }

    fn deployment(mode: &str) -> serde_json::Value {
        json!({
            "mode": mode,
            "networks": {
                "internal": ["198.51.100.0/24", "192.0.2.0/24", "127.0.0.1",
                             "!198.51.100.1", "!198.51.100.5"]
            },
            "trusted_proxies": ["127.0.0.1/32", "198.51.100.1", "198.51.100.5"]
        })
    }

    fn perimeter(mode: &str) -> Perimeter {
        Perimeter::from_config(&internals(), Some(&deployment(mode)))
    }

    #[test]
    fn blocks_match_their_prefix() {
        let c = Cidr::parse("198.51.100.0/24").unwrap();
        assert!(c.contains(ip("198.51.100.77")));
        assert!(!c.contains(ip("203.0.113.1")));
        assert!(c.contains(ip("::ffff:198.51.100.2")));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("203.0.113.9")));
        assert!(Cidr::parse("::1").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
    }

    #[test]
    fn exclusions_take_addresses_out() {
        for spec in [
            json!(["198.51.100.0/24", "!198.51.100.1", "nonsense"]),
            json!("198.51.100.0/24, !198.51.100.1"),
        ] {
            let n = Network::parse("internal", &spec);
            assert!(n.contains(ip("198.51.100.2")));
            assert!(!n.contains(ip("198.51.100.1")));
        }
    }

    #[test]
    fn the_client_is_found_through_trusted_proxies_only() {
        let p = perimeter("enforce");
        let local = Some(ip("127.0.0.1"));
        // A visitor from the internet, through the trusted proxy.
        assert_eq!(p.client(local, &["203.0.113.50"]), Some(ip("203.0.113.50")));
        assert_eq!(
            p.client(local, &["203.0.113.50, 198.51.100.1"]),
            Some(ip("203.0.113.50"))
        );
        // A forged entry to the left of the real one is never reached.
        assert_eq!(
            p.client(local, &["192.0.2.2, 203.0.113.50, 198.51.100.1"]),
            Some(ip("203.0.113.50"))
        );
        // Talking to the core directly, not through a trusted proxy:
        // whatever it puts in the header is ignored.
        assert_eq!(
            p.client(Some(ip("203.0.113.60")), &["192.0.2.2"]),
            Some(ip("203.0.113.60"))
        );
        // An internal client, through the trusted proxy.
        assert_eq!(
            p.client(local, &["198.51.100.7", "198.51.100.1"]),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            p.client(local, &["unknown, 198.51.100.7:51000"]),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn routes_answer_their_networks() {
        let p = perimeter("enforce");
        assert!(p.decide("/public/signup", Some(ip("203.0.113.50"))).allowed);
        assert!(p.decide("/public/status", Some(ip("203.0.113.50"))).allowed);
        assert!(!p.decide("/itm/list", Some(ip("203.0.113.50"))).allowed);
        assert!(p.decide("/itm/list", Some(ip("198.51.100.7"))).allowed);
        assert!(p.decide("/itm/list", Some(ip("192.0.2.2"))).allowed);
        // A trusted proxy is not a member: a request that ends there has
        // lost its client and is refused.
        assert!(!p.decide("/itm/list", Some(ip("198.51.100.1"))).allowed);
        assert!(!p.decide("/itm/list", None).allowed);
    }

    #[test]
    fn the_installation_turns_it_on() {
        // The flavour's rules alone do nothing: a dev install is not locked
        // out of itself.
        assert_eq!(Perimeter::from_config(&internals(), None).mode, Mode::Off);
        // An installation's networks with no rules from the flavour: nothing
        // to enforce.
        assert_eq!(
            Perimeter::from_config(&Item::new(), Some(&deployment("enforce"))).mode,
            Mode::Off
        );
        assert_eq!(perimeter("report").mode, Mode::Report);
        assert_eq!(perimeter("enforce").mode, Mode::Enforce);
    }

    #[test]
    fn anywhere_is_built_in() {
        let p = perimeter("enforce");
        assert!(p.decide("/public/signup", Some(ip("203.0.113.9"))).allowed);
        assert!(p.decide("/public/signup", Some(ip("2001:db8::1"))).allowed);
    }
}
