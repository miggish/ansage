//! Feeds arbitrary bytes to the netlink parser. Must never panic, and every
//! route and nexthop that decodes must survive an encode/decode round trip.

#![no_main]

use herald_netlink::Batch;

use herald_netlink::Body;

use herald_netlink::parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for message in parse(data) {
        let Ok(message) = message else { break };
        let mut batch = Batch::new(1);
        let body = match message.body {
            Ok(Body::Route(route)) => {
                batch.add_route(&route);
                Body::Route(route)
            }
            Ok(Body::Nexthop(nh)) => {
                batch.add_nexthop(&nh);
                Body::Nexthop(nh)
            }
            _ => continue,
        };
        let again: Vec<_> = parse(batch.bytes()).collect();
        assert_eq!(again.len(), 1);
        let again = again.into_iter().next().unwrap().expect("re-encoded message frames");
        assert_eq!(again.body.expect("re-encoded message decodes"), body);
    }
});
