"""
©AngelaMos | 2026
geoip.py
"""

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GeoResult:
    """
    Structured GeoIP lookup result.
    """

    country: str | None
    city: str | None
    lat: float | None
    lon: float | None


class GeoIPService:
    """
    Async GeoIP lookup service backed by a local MaxMind GeoLite2-City database.
    """

    def __init__(self, db_path: str) -> None:
        self._reader: geoip2.database.Reader | None = None
        self._db_path = db_path

        if Path(db_path).is_file():
            self._reader = geoip2.database.Reader(db_path)
            logger.info("GeoIP database loaded from %s", db_path)
        else:
            logger.warning("GeoIP database not found at %s — lookups disabled", db_path)

    async def lookup(self, ip: str) -> GeoResult | None:
        """
        Look up geographic data for an IP address.
        Returns None for private IPs, unknown addresses, or when no database is loaded.
        """
        if self._reader is None:
            return None

        try:
            if ipaddress.ip_address(ip).is_private:
                return None
        except ValueError:
            return None

        try:
            response = await asyncio.to_thread(self._reader.city, ip)
        except AddressNotFoundError:
            return None

        return GeoResult(
            country=response.country.iso_code,
            city=response.city.name,
            lat=response.location.latitude,
            lon=response.location.longitude,
        )

    def swap_reader(self, new_path: str) -> None:
        """
        Atomically replace the database reader after a .mmdb file update.
        """
        old_reader = self._reader
        self._reader = geoip2.database.Reader(new_path)
        self._db_path = new_path
        logger.info("GeoIP reader swapped to %s", new_path)

        if old_reader is not None:
            old_reader.close()

    def close(self) -> None:
        """
        Close the underlying database reader.
        """
        if self._reader is not None:
            self._reader.close()
            self._reader = None
