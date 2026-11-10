use std::net::Ipv4Addr;

use ansage_bgp::wire::{AsPath, LargeCommunity, Origin, PathAttr};

use super::*;
use crate::config::Filter as FilterConfig;

const LOCAL_ASN: u32 = 64500;

fn filter(toml: &str) -> Filter {
    let config: FilterConfig = toml::from_str(toml).unwrap();
    Filter {
        name: "test".into(),
        rules: config.rules,
    }
}

fn attrs(path: &[u32], communities: &[u32]) -> Vec<PathAttr> {
    let mut attrs = vec![
        PathAttr::Origin(Origin::Igp),
        PathAttr::AsPath(AsPath::sequence(path.to_vec())),
    ];
    if !communities.is_empty() {
        attrs.push(PathAttr::Communities(communities.to_vec()));
    }
    attrs
}

fn learned(role: Option<NeighborRole>) -> Source {
    Source::Learned {
        addr: Ipv4Addr::new(198, 51, 100, 2).into(),
        role,
        ibgp: false,
    }
}

fn view<'a>(prefix: &str, source: Source, attrs: &'a [PathAttr]) -> RouteView<'a> {
    RouteView {
        prefix: prefix.parse().unwrap(),
        source,
        attrs,
        local_asn: LOCAL_ASN,
    }
}

#[test]
fn first_matching_rule_decides_and_no_match_rejects() {
    let f = filter(
        r#"
        [[rule]]
        prefixes = ["203.0.113.0/24 le 24"]
        origin_as = [64510]
        action = "accept"
        [[rule]]
        from_role = ["customer"]
        action = "reject"
        "#,
    );
    let a = attrs(&[64510], &[]);
    let customer = learned(Some(NeighborRole::Customer));
    let accepted = f.verdict(&view("203.0.113.0/24", customer, &a));
    assert_eq!(
        accepted,
        Verdict {
            accept: true,
            rule: Some(0)
        }
    );
    let longer = f.verdict(&view("203.0.113.0/25", customer, &a));
    assert_eq!(
        longer,
        Verdict {
            accept: false,
            rule: Some(1)
        }
    );
    let provider = learned(Some(NeighborRole::Provider));
    let unmatched = f.verdict(&view("198.51.100.0/24", provider, &a));
    assert_eq!(
        unmatched,
        Verdict {
            accept: false,
            rule: None
        }
    );
}

#[test]
fn conditions() {
    let a = attrs(&[64501, 3356, 64510], &[64500 << 16 | 200]);
    let from = learned(Some(NeighborRole::Provider));
    let hit = |rule: &str, source: Source| {
        filter(&format!("[[rule]]\n{rule}\naction = \"accept\"\n"))
            .verdict(&view("192.0.2.0/24", source, &a))
            .accept
    };
    assert!(hit(r#"source = "learned""#, from));
    assert!(!hit(r#"source = "own""#, from));
    assert!(hit(r#"source = "own""#, Source::Own));
    assert!(!hit(r#"from_role = ["customer"]"#, from));
    assert!(hit(r#"from_neighbor = ["198.51.100.2"]"#, from));
    assert!(hit("origin_as = [64510]", from));
    assert!(!hit("origin_as = [3356]", from));
    assert!(hit("as_path_contains = [3356]", from));
    assert!(hit("as_path_max_len = 3", from));
    assert!(!hit("as_path_max_len = 2", from));
    assert!(hit(r#"communities = ["64500:200", "1:1"]"#, from));
    assert!(!hit(r#"communities = ["64500:201"]"#, from));
    assert!(!hit(r#"large_communities = ["64500:1:2"]"#, from));
    // Own routes have an empty path: we are their origin.
    let own = attrs(&[], &[]);
    let rule = filter("[[rule]]\norigin_as = [64500]\naction = \"accept\"\n");
    assert!(
        rule.verdict(&view("192.0.2.0/24", Source::Own, &own))
            .accept
    );
}

#[test]
fn apply_changes() {
    let f = filter(
        r#"
        [[rule]]
        action = "accept"
        prepend = 2
        add_communities = ["64500:1"]
        remove_communities = ["64510:9"]
        add_large_communities = ["64500:1:2"]
        med = 10
        "#,
    );
    let mut a = attrs(&[64500, 64510], &[64510 << 16 | 9]);
    apply(&f.rules[0], &mut a, LOCAL_ASN);
    assert_eq!(
        a,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([64500, 64500, 64500, 64510])),
            PathAttr::MultiExitDisc(10),
            PathAttr::Communities(vec![64500 << 16 | 1]),
            PathAttr::LargeCommunities(vec![LargeCommunity {
                global_admin: 64500,
                local_data_1: 1,
                local_data_2: 2,
            }]),
        ]
    );
    // Removing the last community drops the attribute.
    let f = filter("[[rule]]\naction = \"accept\"\nremove_communities = [\"64500:1\"]\n");
    apply(&f.rules[0], &mut a, LOCAL_ASN);
    assert!(!a.iter().any(|a| matches!(a, PathAttr::Communities(_))));
}

#[test]
fn ingress_otc() {
    use NeighborRole::*;
    let plain = attrs(&[64501], &[]);
    let mut marked = plain.clone();
    marked.push(PathAttr::OnlyToCustomer(64501));
    assert_eq!(ingress(None, 64501, &marked), Ok(None), "no role, no check");
    assert!(ingress(Some(Customer), 64501, &marked).is_err());
    assert_eq!(ingress(Some(Customer), 64501, &plain), Ok(None));
    assert_eq!(ingress(Some(Peer), 64501, &marked), Ok(None));
    assert!(
        ingress(Some(Peer), 64999, &marked).is_err(),
        "OTC of another AS"
    );
    for role in [Provider, Peer, Rs] {
        assert_eq!(
            ingress(Some(role), 64501, &plain),
            Ok(Some(PathAttr::OnlyToCustomer(64501)))
        );
    }
    assert_eq!(ingress(Some(Provider), 64501, &marked), Ok(None), "kept");
}

#[test]
fn leak_guard() {
    use NeighborRole::*;
    let a = attrs(&[64501], &[]);
    let roles = [Provider, Customer, Peer, Rs];
    for target in roles {
        assert!(guard(Source::Own, Some(target), &a).is_ok());
        assert!(guard(learned(Some(Customer)), Some(target), &a).is_ok());
        for from in [Provider, Peer, Rs] {
            assert_eq!(
                guard(learned(Some(from)), Some(target), &a).is_ok(),
                target == Customer,
                "{from:?} -> {target:?}"
            );
        }
    }
    assert!(guard(Source::Own, None, &a).is_ok());
    assert!(guard(learned(Some(Customer)), None, &a).is_err());
    assert!(guard(learned(None), Some(Customer), &a).is_err());
    let ibgp = Source::Learned {
        addr: Ipv4Addr::new(10, 0, 0, 2).into(),
        role: None,
        ibgp: true,
    };
    assert!(guard(ibgp, Some(Customer), &a).is_ok());
    assert!(guard(ibgp, Some(Provider), &a).is_err());

    for community in [0xFFFF_FF01, 0xFFFF_FF02, 0xFFFF_FF03] {
        let tagged = attrs(&[64501], &[community]);
        assert!(guard(learned(Some(Customer)), Some(Customer), &tagged).is_err());
    }

    let mut marked = a.clone();
    marked.push(PathAttr::OnlyToCustomer(64999));
    assert!(guard(learned(Some(Customer)), Some(Customer), &marked).is_ok());
    assert!(guard(learned(Some(Customer)), Some(Peer), &marked).is_err());
}

#[test]
fn egress_otc() {
    use NeighborRole::*;
    let a = attrs(&[], &[]);
    let otc = Some(PathAttr::OnlyToCustomer(LOCAL_ASN));
    assert_eq!(egress(Some(Customer), LOCAL_ASN, &a), otc);
    assert_eq!(egress(Some(Peer), LOCAL_ASN, &a), otc);
    assert_eq!(egress(Some(Provider), LOCAL_ASN, &a), None);
    assert_eq!(egress(Some(Rs), LOCAL_ASN, &a), None);
    assert_eq!(egress(None, LOCAL_ASN, &a), None);
    let mut marked = a.clone();
    marked.push(PathAttr::OnlyToCustomer(64999));
    assert_eq!(
        egress(Some(Customer), LOCAL_ASN, &marked),
        None,
        "kept as is"
    );
}
