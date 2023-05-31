use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_resolver::config::NameServerConfigGroup;
use trust_dns_server::{
    authority::Catalog,
    client::rr::RrKey,
    proto::rr::{Name, Record, RecordSet},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
    ServerFuture,
};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct DNSName(Name);

impl Serialize for DNSName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct DNSNameVisitor;

impl Visitor<'_> for DNSNameVisitor {
    type Value = DNSName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting a DNS name")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(DNSName(match Name::parse(v, None) {
            Ok(res) => res,
            Err(e) => return Err(serde::de::Error::custom(e)),
        }))
    }
}

impl<'de> Deserialize<'de> for DNSName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(DNSNameVisitor)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Records(BTreeMap<DNSName, BTreeMap<DNSName, Ipv4Addr>>);

fn generate_a(name: DNSName, address: Ipv4Addr) -> RecordSet {
    let mut v4rs = RecordSet::new(&name.0, trust_dns_server::proto::rr::RecordType::A, 30);

    let mut rec = Record::with(
        name.0.clone(),
        trust_dns_server::proto::rr::RecordType::A,
        30,
    );
    rec.set_data(Some(trust_dns_server::proto::rr::RData::A(address)));

    v4rs.insert(rec, 1);
    v4rs
}

fn generate_soa(domain: DNSName) -> RecordSet {
    let mut rs = RecordSet::new(&domain.0, trust_dns_server::proto::rr::RecordType::SOA, 30);

    let mut rec = Record::with(
        domain.0.clone(),
        trust_dns_server::proto::rr::RecordType::SOA,
        30,
    );

    rec.set_data(Some(trust_dns_server::proto::rr::RData::SOA(
        trust_dns_server::proto::rr::rdata::SOA::new(
            domain.0.clone(),
            Name::from_utf8(format!("administrator.{}", domain.0)).unwrap(),
            1,
            60,
            1,
            120,
            30,
        ),
    )));

    rs.insert(rec, 1);
    rs
}

fn generate_catalog(records: Records) -> Result<Catalog, anyhow::Error> {
    let mut catalog = Catalog::default();

    for (domain, recs) in records.0 {
        let mut rc = BTreeMap::default();
        for (name, rec) in recs {
            rc.insert(
                RrKey::new(
                    domain.0.clone().into(),
                    trust_dns_server::proto::rr::RecordType::SOA,
                ),
                generate_soa(domain.clone()),
            );

            let a_rec = generate_a(name.clone(), rec);

            rc.insert(RrKey::new(name.0.into(), a_rec.record_type()), a_rec);
        }

        let authority = InMemoryAuthority::new(
            domain.0.clone().into(),
            rc,
            trust_dns_server::authority::ZoneType::Primary,
            false,
        )
        .unwrap();

        catalog.upsert(domain.0.into(), Box::new(Arc::new(authority)));
    }

    let resolv = trust_dns_resolver::system_conf::read_system_conf()?;
    let mut nsconfig = NameServerConfigGroup::new();

    for server in resolv.0.name_servers() {
        nsconfig.push(server.clone());
    }

    let options = Some(resolv.1);
    let config = &ForwardConfig {
        name_servers: nsconfig.clone(),
        options,
    };

    let forwarder = ForwardAuthority::try_from_config(
        Name::root(),
        trust_dns_server::authority::ZoneType::Primary,
        config,
    )
    .expect("Could not boot forwarder");

    catalog.upsert(Name::root().into(), Box::new(Arc::new(forwarder)));

    Ok(catalog)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut f = std::fs::OpenOptions::new();
    f.read(true);
    let io = f.open("examplens.yaml")?;

    let records: Records = serde_yaml::from_reader(io)?;

    let sa = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5300);
    let tcp = TcpListener::bind(sa).await?;
    let udp = UdpSocket::bind(sa).await?;

    let mut sf = ServerFuture::new(generate_catalog(records)?);
    sf.register_socket(udp);
    sf.register_listener(tcp, Duration::new(60, 0));
    match sf.block_until_done().await {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!(e)),
    }
}
