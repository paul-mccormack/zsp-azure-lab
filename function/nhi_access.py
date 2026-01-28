"""
Non-Human Identity Access Management

Handles granting/revoking Azure RBAC role assignments for service principals.
"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters


# Common role definition IDs (built-in roles)
ROLE_DEFINITIONS = {
    "Key Vault Secrets User": "4633458b-17de-408a-b874-0445c86b69e6",
    "Key Vault Secrets Officer": "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "Key Vault Reader": "21090545-7ca7-4776-b22c-e363652d74d2",
    "Storage Blob Data Reader": "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
}


def get_subscription_id_from_scope(scope: str) -> str:
    """Extract subscription ID from a resource scope."""
    parts = scope.split("/")
    if "subscriptions" in parts:
        idx = parts.index("subscriptions")
        return parts[idx + 1]
    raise ValueError(f"Could not extract subscription ID from scope: {scope}")


def get_role_definition_id(role_name: str, subscription_id: str) -> str:
    """Get the full role definition ID for a role name."""
    if role_name in ROLE_DEFINITIONS:
        role_guid = ROLE_DEFINITIONS[role_name]
        return f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_guid}"
    raise ValueError(f"Unknown role: {role_name}. Add it to ROLE_DEFINITIONS.")


async def grant_nhi_access(
    sp_object_id: str,
    scope: str,
    role_name: str,
    duration_minutes: int,
    workflow_id: str
) -> dict:
    """
    Grant temporary role assignment to a service principal.

    Args:
        sp_object_id: Object ID of the service principal
        scope: Resource scope (e.g., Key Vault resource ID)
        role_name: The role to assign (e.g., "Key Vault Secrets User")
        duration_minutes: How long access should last
        workflow_id: Identifier for the triggering workflow

    Returns:
        dict with assignment details
    """
    logging.info(f"Granting NHI access: sp={sp_object_id}, scope={scope}, role={role_name}, duration={duration_minutes}m")

    credential = DefaultAzureCredential()
    subscription_id = get_subscription_id_from_scope(scope)

    auth_client = AuthorizationManagementClient(credential, subscription_id)

    # Generate unique assignment name
    assignment_name = str(uuid.uuid4())

    # Get role definition ID
    role_definition_id = get_role_definition_id(role_name, subscription_id)

    # Create role assignment
    assignment_params = RoleAssignmentCreateParameters(
        role_definition_id=role_definition_id,
        principal_id=sp_object_id,
        principal_type="ServicePrincipal"
    )

    assignment = auth_client.role_assignments.create(
        scope=scope,
        role_assignment_name=assignment_name,
        parameters=assignment_params
    )

    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

    logging.info(f"Role assignment created: {assignment.id}, expires at {expiry_time.isoformat()}")

    return {
        "status": "granted",
        "assignment_id": assignment.id,
        "assignment_name": assignment_name,
        "sp_object_id": sp_object_id,
        "scope": scope,
        "role": role_name,
        "expires_at": expiry_time.isoformat(),
        "duration_minutes": duration_minutes,
        "workflow_id": workflow_id
    }


async def revoke_nhi_access(assignment_id: str) -> dict:
    """
    Revoke NHI access by deleting the role assignment.

    Args:
        assignment_id: The full resource ID of the role assignment

    Returns:
        dict with revocation status
    """
    logging.info(f"Revoking NHI access: assignment={assignment_id}")

    credential = DefaultAzureCredential()

    # Extract subscription ID from assignment ID
    # Format: /subscriptions/{sub}/providers/.../roleAssignments/{name}
    # or: /subscriptions/{sub}/resourceGroups/{rg}/providers/.../roleAssignments/{name}
    parts = assignment_id.split("/")
    subscription_id = parts[parts.index("subscriptions") + 1]

    auth_client = AuthorizationManagementClient(credential, subscription_id)

    try:
        # Delete by ID
        auth_client.role_assignments.delete_by_id(assignment_id)
        logging.info(f"Role assignment deleted: {assignment_id}")

        return {
            "status": "revoked",
            "assignment_id": assignment_id,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        # Assignment might have been deleted manually or already expired
        logging.warning(f"Could not delete role assignment: {e}")
        return {
            "status": "already_revoked",
            "assignment_id": assignment_id,
            "error": str(e)
        }


async def list_sp_role_assignments(sp_object_id: str, subscription_id: str) -> list:
    """
    List all role assignments for a service principal.
    Useful for auditing/verification.
    """
    credential = DefaultAzureCredential()
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    assignments = auth_client.role_assignments.list_for_subscription(
        filter=f"principalId eq '{sp_object_id}'"
    )

    return [
        {
            "id": a.id,
            "scope": a.scope,
            "role_definition_id": a.role_definition_id,
            "created": a.created_on.isoformat() if a.created_on else None
        }
        for a in assignments
    ]
