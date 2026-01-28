"""
Zero Standing Privilege Gateway - Azure Function App

Handles access requests for both human administrators and non-human identities.
All access is time-bounded and automatically revoked.
"""

import azure.functions as func
import azure.durable_functions as df
import logging
import json
import os
from datetime import datetime, timedelta, timezone

from admin_access import grant_admin_access, revoke_admin_access
from nhi_access import grant_nhi_access, revoke_nhi_access
from audit import log_access_event

app = df.DFApp(http_auth_level=func.AuthLevel.FUNCTION)

# =============================================================================
# HTTP TRIGGERS - Access Request Endpoints
# =============================================================================

@app.route(route="human-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def admin_access_request(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Handle human admin access requests.

    Request body:
    {
        "user_id": "entra-user-object-id",
        "group_id": "zsp-group-object-id",
        "duration_minutes": 60,
        "justification": "Reason for access",
        "ticket_id": "INC0012345" (optional)
    }
    """
    logging.info("Admin access request received")

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate required fields
    required_fields = ["user_id", "group_id", "duration_minutes", "justification"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        return func.HttpResponse(
            json.dumps({"error": f"Missing required fields: {missing}"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate duration
    max_duration = int(os.environ.get("MAX_ACCESS_DURATION_MINUTES", 480))
    if body["duration_minutes"] > max_duration:
        return func.HttpResponse(
            json.dumps({"error": f"Duration exceeds maximum of {max_duration} minutes"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate justification length
    if len(body["justification"]) < 10:
        return func.HttpResponse(
            json.dumps({"error": "Justification must be at least 10 characters"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        result = await grant_admin_access(
            user_id=body["user_id"],
            group_id=body["group_id"],
            duration_minutes=body["duration_minutes"],
            justification=body["justification"],
            ticket_id=body.get("ticket_id")
        )

        # Schedule revocation via Durable Functions orchestrator
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=body["duration_minutes"])
        instance_id = await client.start_new(
            "revocation_orchestrator",
            client_input={
                "revocation_type": "group_membership",
                "user_id": body["user_id"],
                "group_id": body["group_id"],
                "expiry_time": expiry_time.isoformat()
            }
        )
        logging.info(f"Revocation orchestrator started: {instance_id}, expires at {expiry_time.isoformat()}")

        # Log successful grant
        await log_access_event(
            event_type="AccessGrant",
            identity_type="human",
            principal_id=body["user_id"],
            target=body["group_id"],
            target_type="EntraGroup",
            duration_minutes=body["duration_minutes"],
            justification=body["justification"],
            ticket_id=body.get("ticket_id"),
            expires_at=result["expires_at"],
            result="Success"
        )

        result["orchestrator_instance_id"] = instance_id

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Admin access grant failed: {str(e)}")

        # Log failure
        await log_access_event(
            event_type="AccessGrant",
            identity_type="human",
            principal_id=body["user_id"],
            target=body["group_id"],
            target_type="EntraGroup",
            duration_minutes=body["duration_minutes"],
            justification=body["justification"],
            result="Failed",
            error_message=str(e)
        )

        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


@app.route(route="nhi-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def nhi_access_request(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Handle non-human identity access requests.

    Request body:
    {
        "sp_object_id": "service-principal-object-id",
        "scope": "/subscriptions/.../resourceGroups/.../providers/...",
        "role": "Key Vault Secrets User",
        "duration_minutes": 30,
        "workflow_id": "nightly-backup"
    }
    """
    logging.info("NHI access request received")

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate required fields
    required_fields = ["sp_object_id", "scope", "role", "duration_minutes", "workflow_id"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        return func.HttpResponse(
            json.dumps({"error": f"Missing required fields: {missing}"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate duration
    max_duration = int(os.environ.get("MAX_ACCESS_DURATION_MINUTES", 480))
    if body["duration_minutes"] > max_duration:
        return func.HttpResponse(
            json.dumps({"error": f"Duration exceeds maximum of {max_duration} minutes"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        result = await grant_nhi_access(
            sp_object_id=body["sp_object_id"],
            scope=body["scope"],
            role_name=body["role"],
            duration_minutes=body["duration_minutes"],
            workflow_id=body["workflow_id"]
        )

        # Schedule revocation via Durable Functions orchestrator
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=body["duration_minutes"])
        instance_id = await client.start_new(
            "revocation_orchestrator",
            client_input={
                "revocation_type": "role_assignment",
                "assignment_id": result["assignment_id"],
                "sp_object_id": body["sp_object_id"],
                "scope": body["scope"],
                "role": body["role"],
                "expiry_time": expiry_time.isoformat()
            }
        )
        logging.info(f"Revocation orchestrator started: {instance_id}, expires at {expiry_time.isoformat()}")

        # Log successful grant
        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=body["sp_object_id"],
            target=body["scope"],
            target_type="AzureResource",
            role=body["role"],
            duration_minutes=body["duration_minutes"],
            workflow_id=body["workflow_id"],
            expires_at=result["expires_at"],
            result="Success"
        )

        result["orchestrator_instance_id"] = instance_id

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"NHI access grant failed: {str(e)}")

        # Log failure
        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=body["sp_object_id"],
            target=body["scope"],
            target_type="AzureResource",
            role=body["role"],
            duration_minutes=body["duration_minutes"],
            workflow_id=body["workflow_id"],
            result="Failed",
            error_message=str(e)
        )

        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


# =============================================================================
# TIMER TRIGGERS - Scheduled NHI Access
# =============================================================================

@app.timer_trigger(schedule="%BACKUP_JOB_SCHEDULE%", arg_name="timer", run_on_startup=False)
@app.durable_client_input(client_name="client")
async def backup_job_access_grant(timer: func.TimerRequest, client):
    """
    Grant backup service principal access before the nightly job runs.
    Triggered by schedule (default: 1:55 AM daily).
    """
    logging.info("Backup job access grant triggered")

    sp_object_id = os.environ.get("BACKUP_SP_OBJECT_ID")
    keyvault_id = os.environ.get("KEYVAULT_RESOURCE_ID")
    storage_id = os.environ.get("STORAGE_RESOURCE_ID")
    duration = int(os.environ.get("BACKUP_JOB_DURATION_MINUTES", 35))

    if not all([sp_object_id, keyvault_id, storage_id]):
        logging.error("Missing environment variables for backup job")
        return

    try:
        # Grant Key Vault access
        kv_result = await grant_nhi_access(
            sp_object_id=sp_object_id,
            scope=keyvault_id,
            role_name="Key Vault Secrets User",
            duration_minutes=duration,
            workflow_id="nightly-backup"
        )

        # Grant Storage access
        stor_result = await grant_nhi_access(
            sp_object_id=sp_object_id,
            scope=storage_id,
            role_name="Storage Blob Data Contributor",
            duration_minutes=duration,
            workflow_id="nightly-backup"
        )

        # Schedule revocation for both grants
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=duration)
        for grant_result, scope, role in [
            (kv_result, keyvault_id, "Key Vault Secrets User"),
            (stor_result, storage_id, "Storage Blob Data Contributor"),
        ]:
            await client.start_new(
                "revocation_orchestrator",
                client_input={
                    "revocation_type": "role_assignment",
                    "assignment_id": grant_result["assignment_id"],
                    "sp_object_id": sp_object_id,
                    "scope": scope,
                    "role": role,
                    "expiry_time": expiry_time.isoformat()
                }
            )

        logging.info(f"Backup SP granted access for {duration} minutes with scheduled revocation")

    except Exception as e:
        logging.error(f"Backup job access grant failed: {str(e)}")


# =============================================================================
# DURABLE FUNCTIONS - Scheduled Revocation
# =============================================================================

@app.orchestration_trigger(context_name="context")
def revocation_orchestrator(context: df.DurableOrchestrationContext):
    """
    Orchestrator that waits until expiry time, then revokes access.
    """
    input_data = context.get_input()

    # Wait until the specified expiry time
    # Ensure timezone-aware to match context.current_utc_datetime
    expiry_time = datetime.fromisoformat(input_data["expiry_time"]).replace(tzinfo=timezone.utc)
    yield context.create_timer(expiry_time)

    # Execute revocation
    if input_data["revocation_type"] == "group_membership":
        yield context.call_activity("revoke_group_membership_activity", input_data)
    elif input_data["revocation_type"] == "role_assignment":
        yield context.call_activity("revoke_role_assignment_activity", input_data)

    return {"status": "revoked", "completed_at": datetime.now(timezone.utc).isoformat()}


@app.activity_trigger(input_name="activityPayload")
def revoke_group_membership_activity(activityPayload: str):
    """
    Activity to remove a user from a group.
    """
    import asyncio
    input_data = json.loads(activityPayload) if isinstance(activityPayload, str) else activityPayload

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(revoke_admin_access(
            user_id=input_data["user_id"],
            group_id=input_data["group_id"]
        ))
        loop.run_until_complete(log_access_event(
            event_type="AccessRevoke",
            identity_type="human",
            principal_id=input_data["user_id"],
            target=input_data["group_id"],
            target_type="EntraGroup",
            result="Success"
        ))
    finally:
        loop.close()

    return {"status": "revoked"}


@app.activity_trigger(input_name="activityPayload")
def revoke_role_assignment_activity(activityPayload: str):
    """
    Activity to delete a role assignment.
    """
    import asyncio
    input_data = json.loads(activityPayload) if isinstance(activityPayload, str) else activityPayload

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(revoke_nhi_access(
            assignment_id=input_data["assignment_id"]
        ))
        loop.run_until_complete(log_access_event(
            event_type="AccessRevoke",
            identity_type="nhi",
            principal_id=input_data["sp_object_id"],
            target=input_data["scope"],
            target_type="AzureResource",
            role=input_data.get("role"),
            result="Success"
        ))
    finally:
        loop.close()

    return {"status": "revoked"}


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Simple health check endpoint."""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0"
        }),
        status_code=200,
        mimetype="application/json"
    )
