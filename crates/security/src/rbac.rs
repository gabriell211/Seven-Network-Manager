use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Permission(String);

impl Permission {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorizationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.contains('.')
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(AuthorizationError::InvalidPermission);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceScope {
    pub organization_id: Uuid,
    pub site_id: Option<Uuid>,
}

impl ResourceScope {
    pub fn contains(self, requested: Self) -> bool {
        self.organization_id == requested.organization_id
            && (self.site_id.is_none() || self.site_id == requested.site_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrant {
    pub permission: Permission,
    pub scope: ResourceScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContext {
    pub actor_id: Uuid,
    pub session_id: Uuid,
    pub grants: Vec<PermissionGrant>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub permission: Permission,
    pub scope: ResourceScope,
}

impl AuthorizationContext {
    pub fn authorize(&self, request: &AuthorizationRequest) -> Result<(), AuthorizationError> {
        let allowed = self.grants.iter().any(|grant| {
            grant.permission == request.permission && grant.scope.contains(request.scope)
        });
        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }

    pub fn authorize_approval(
        &self,
        request: &AuthorizationRequest,
        requested_by: Uuid,
        require_separation_of_duties: bool,
    ) -> Result<(), AuthorizationError> {
        self.authorize(request)?;
        if require_separation_of_duties && self.actor_id == requested_by {
            return Err(AuthorizationError::SelfApprovalDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("permission identifier is invalid")]
    InvalidPermission,
    #[error("authorization denied")]
    Denied,
    #[error("requester cannot approve their own privileged operation")]
    SelfApprovalDenied,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permission(value: &str) -> Permission {
        Permission::parse(value).unwrap()
    }

    #[test]
    fn organization_scope_does_not_cross_organization_boundary() {
        let org_a = Uuid::now_v7();
        let org_b = Uuid::now_v7();
        let context = AuthorizationContext {
            actor_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            grants: vec![PermissionGrant {
                permission: permission("devices.view"),
                scope: ResourceScope {
                    organization_id: org_a,
                    site_id: None,
                },
            }],
        };
        assert_eq!(
            context
                .authorize(&AuthorizationRequest {
                    permission: permission("devices.view"),
                    scope: ResourceScope {
                        organization_id: org_b,
                        site_id: None,
                    },
                })
                .unwrap_err(),
            AuthorizationError::Denied
        );
    }

    #[test]
    fn site_grant_cannot_escalate_to_sibling_site() {
        let organization_id = Uuid::now_v7();
        let site_a = Uuid::now_v7();
        let site_b = Uuid::now_v7();
        let context = AuthorizationContext {
            actor_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            grants: vec![PermissionGrant {
                permission: permission("vlans.write"),
                scope: ResourceScope {
                    organization_id,
                    site_id: Some(site_a),
                },
            }],
        };
        assert!(context
            .authorize(&AuthorizationRequest {
                permission: permission("vlans.write"),
                scope: ResourceScope {
                    organization_id,
                    site_id: Some(site_a),
                },
            })
            .is_ok());
        assert_eq!(
            context
                .authorize(&AuthorizationRequest {
                    permission: permission("vlans.write"),
                    scope: ResourceScope {
                        organization_id,
                        site_id: Some(site_b),
                    },
                })
                .unwrap_err(),
            AuthorizationError::Denied
        );
    }

    #[test]
    fn approval_can_require_distinct_actor() {
        let actor = Uuid::now_v7();
        let org = Uuid::now_v7();
        let request = AuthorizationRequest {
            permission: permission("changes.approve"),
            scope: ResourceScope {
                organization_id: org,
                site_id: None,
            },
        };
        let context = AuthorizationContext {
            actor_id: actor,
            session_id: Uuid::now_v7(),
            grants: vec![PermissionGrant {
                permission: permission("changes.approve"),
                scope: ResourceScope {
                    organization_id: org,
                    site_id: None,
                },
            }],
        };
        assert_eq!(
            context
                .authorize_approval(&request, actor, true)
                .unwrap_err(),
            AuthorizationError::SelfApprovalDenied
        );
    }
}
