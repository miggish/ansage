//! Our own prefixes and the drain (RFC 8326).

use std::time::Instant;

use herald_bgp::wire::AsPath;

use herald_bgp::wire::GRACEFUL_SHUTDOWN;

use herald_bgp::wire::Origin;

use herald_bgp::wire::PathAttr;

use herald_bgp::wire::Prefix;
use tracing::info;

use super::{
    Rib,
    msg::{DrainChange, OwnChange},
    table::{LOCAL, Route},
};

impl Rib {
    /// Starts or ends a drain: our own routes are inserted again with the
    /// drain attributes (or without), and the usual dirty tracking sends
    /// them to every peer.
    pub(super) fn drain(&mut self, drained: bool, now: Instant) -> DrainChange {
        if drained == self.drained.is_some() {
            return DrainChange {
                changed: false,
                since: self.drained,
            };
        }
        self.drained = drained.then_some(now);
        for prefix in self.config.announce.clone() {
            self.insert_own(prefix);
        }
        if drained {
            info!(
                prefixes = self.config.announce.len(),
                "drained: own routes go out with GRACEFUL_SHUTDOWN"
            );
        } else {
            info!("drain ended: own routes go out as usual");
        }
        DrainChange {
            changed: true,
            since: self.drained,
        }
    }

    /// Announces or withdraws our own prefixes; exports follow through the
    /// usual dirty tracking.
    pub(super) fn own(&mut self, announce: bool, prefixes: Vec<Prefix>) -> OwnChange {
        let mut change = OwnChange::default();
        for prefix in prefixes {
            let present = self.config.announce.contains(&prefix);
            if present == announce {
                if !change.unchanged.contains(&prefix) {
                    change.unchanged.push(prefix);
                }
                continue;
            }
            if announce {
                self.insert_own(prefix);
                self.config.announce.push(prefix);
            } else {
                self.withdraw(LOCAL, prefix);
                self.config.announce.retain(|p| *p != prefix);
            }
            change.changed.push(prefix);
        }
        if !change.changed.is_empty() {
            info!(announce, prefixes = ?change.changed, "own prefixes changed at runtime");
        }
        change
    }

    pub(super) fn insert_own(&mut self, prefix: Prefix) {
        self.protected.insert(prefix);
        // An empty AS_PATH; the local AS, next hop and LOCAL_PREF are added
        // per peer on export. Drained (RFC 8326): LOCAL_PREF 0 (kept on
        // iBGP only) and GRACEFUL_SHUTDOWN.
        let mut own = vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::default()),
        ];
        if self.drained.is_some() {
            own.push(PathAttr::LocalPref(0));
            own.push(PathAttr::Communities(vec![GRACEFUL_SHUTDOWN]));
        }
        let attrs = self.pool.intern(&own, None);
        self.insert(
            prefix,
            Route {
                source: LOCAL,
                attrs,
            },
        );
    }
}
