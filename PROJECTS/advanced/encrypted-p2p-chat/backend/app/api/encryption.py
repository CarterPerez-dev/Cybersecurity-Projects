"""
©AngelaMos | 2026
encryption.py
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.Base import get_session
from app.services.prekey_service import PreKeyBundle, prekey_service


logger = logging.getLogger(__name__)

router = APIRouter(prefix = "/encryption", tags = ["encryption"])


class ClientKeysUpload(BaseModel):
    """
    Request body for uploading client generated public keys
    """
    identity_key: str
    identity_key_ed25519: str
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekeys: list[str]


@router.get(
    "/prekey-bundle/{user_id}",
    status_code = status.HTTP_200_OK,
    response_model = PreKeyBundle,
)
async def get_prekey_bundle(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> PreKeyBundle:
    """
    Returns a prekey bundle for initiating X3DH with the target user
    """
    bundle = await prekey_service.get_prekey_bundle(session, user_id)
    return bundle


@router.post("/upload-keys/{user_id}", status_code = status.HTTP_201_CREATED)
async def upload_client_keys(
    user_id: UUID,
    keys: ClientKeysUpload,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          str]:
    """
    Stores client generated public keys for E2E encryption
    """
    await prekey_service.store_client_keys(
        session,
        user_id,
        keys.identity_key,
        keys.identity_key_ed25519,
        keys.signed_prekey,
        keys.signed_prekey_signature,
        keys.one_time_prekeys,
    )
    return {
        "status": "success",
        "message": f"Stored client keys for user {user_id}",
    }
