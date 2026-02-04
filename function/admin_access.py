"""
Human Administrator Access Management

Handles adding/removing users to/from ZSP security groups.
"""

import logging
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.reference_create import ReferenceCreate


async def grant_admin_access(
    user_id: str,
    group_id: str,
    duration_minutes: int,
    justification: str,
    ticket_id: str | None = None
) -> dict:
    """
    Grant temporary admin access by adding user to ZSP group.

    Args:
        user_id: Entra object ID of the requesting user
        group_id: Object ID of the ZSP security group
        duration_minutes: How long access should last
        justification: Required reason for access
        ticket_id: Optional ITSM ticket reference

    Returns:
        dict with grant details and expiry time
    """
    logging.info(f"Granting admin access: user={user_id}, group={group_id}, duration={duration_minutes}m")

    # Initialize Graph client with managed identity
    credential = DefaultAzureCredential()
    graph_client = GraphServiceClient(credential)

    # Check if user is already a member
    try:
        members = await graph_client.groups.by_group_id(group_id).members.get()
        existing_member_ids = [m.id for m in members.value] if members.value else []

        if user_id in existing_member_ids:
            logging.warning(f"User {user_id} is already a member of group {group_id}")
            # Could choose to extend or reject - for now, we'll just note it
    except Exception as e:
        logging.warning(f"Could not check existing membership: {e}")

    # Add user to group (handle duplicate membership gracefully)
    request_body = ReferenceCreate(
        odata_id=f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    )

    try:
        await graph_client.groups.by_group_id(group_id).members.ref.post(request_body)
    except Exception as e:
        error_msg = str(e).lower()
        if "already exist" in error_msg or "added object references already exist" in error_msg:
            logging.info(f"User {user_id} is already a member of group {group_id}, treating as success")
        else:
            raise

    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

    logging.info(f"User {user_id} added to group {group_id}, expires at {expiry_time.isoformat()}")

    return {
        "status": "granted",
        "user_id": user_id,
        "group_id": group_id,
        "expires_at": expiry_time.isoformat(),
        "duration_minutes": duration_minutes,
        "justification": justification,
        "ticket_id": ticket_id
    }


async def revoke_admin_access(user_id: str, group_id: str) -> dict:
    """
    Revoke admin access by removing user from ZSP group.

    Args:
        user_id: Entra object ID of the user to remove
        group_id: Object ID of the ZSP security group

    Returns:
        dict with revocation status
    """
    logging.info(f"Revoking admin access: user={user_id}, group={group_id}")

    credential = DefaultAzureCredential()
    graph_client = GraphServiceClient(credential)

    try:
        await graph_client.groups.by_group_id(group_id).members.by_directory_object_id(user_id).ref.delete()
        logging.info(f"User {user_id} removed from group {group_id}")

        return {
            "status": "revoked",
            "user_id": user_id,
            "group_id": group_id,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        # User might have been removed manually or already expired
        logging.warning(f"Could not remove user from group: {e}")
        return {
            "status": "already_revoked",
            "user_id": user_id,
            "group_id": group_id,
            "error": str(e)
        }


async def get_user_display_name(user_id: str) -> str | None:
    """Get the display name for a user ID (for logging)."""
    try:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)
        user = await graph_client.users.by_user_id(user_id).get()
        return user.display_name if user else None
    except Exception:
        return None


async def get_group_display_name(group_id: str) -> str | None:
    """Get the display name for a group ID (for logging)."""
    try:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)
        group = await graph_client.groups.by_group_id(group_id).get()
        return group.display_name if group else None
    except Exception:
        return None
