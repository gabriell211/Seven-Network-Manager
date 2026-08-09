use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OrganizationId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SiteId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RoutingDomainId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDomain {
    pub id: RoutingDomainId,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub name: String,
    pub vrf_name: Option<String>,
    pub description: Option<String>,
}

impl RoutingDomain {
    pub fn default_lan(organization_id: OrganizationId, site_id: SiteId) -> Self {
        Self {
            id: RoutingDomainId(Uuid::new_v4()),
            organization_id,
            site_id,
            name: "default".to_string(),
            vrf_name: None,
            description: Some("Default LAN routing domain".to_string()),
        }
    }
}
