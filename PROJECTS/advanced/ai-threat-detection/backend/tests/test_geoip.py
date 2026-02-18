"""
©AngelaMos | 2026
test_geoip.py
"""

from unittest.mock import MagicMock, patch

import pytest

from app.core.enrichment.geoip import GeoIPService, GeoResult


def _mock_city_response(
    country_iso: str = "US",
    city_name: str = "Los Angeles",
    lat: float = 34.0522,
    lon: float = -118.2437,
) -> MagicMock:
    """
    Build a mock geoip2 City response object.
    """
    response = MagicMock()
    response.country.iso_code = country_iso
    response.city.name = city_name
    response.location.latitude = lat
    response.location.longitude = lon
    return response


@pytest.fixture
def mock_reader() -> MagicMock:
    """
    A mock geoip2 database reader.
    """
    reader = MagicMock()
    reader.city.return_value = _mock_city_response()
    return reader


def test_geo_result_fields() -> None:
    """
    GeoResult stores country, city, latitude, and longitude.
    """
    result = GeoResult(country="US", city="Seattle", lat=47.6, lon=-122.3)
    assert result.country == "US"
    assert result.city == "Seattle"
    assert result.lat == 47.6
    assert result.lon == -122.3


@pytest.mark.asyncio
async def test_lookup_returns_geo_result(mock_reader) -> None:
    """
    Successful lookup returns a populated GeoResult.
    """
    service = GeoIPService.__new__(GeoIPService)
    service._reader = mock_reader

    result = await service.lookup("8.8.8.8")
    assert result is not None
    assert result.country == "US"
    assert result.city == "Los Angeles"
    assert result.lat == pytest.approx(34.0522)
    assert result.lon == pytest.approx(-118.2437)


@pytest.mark.asyncio
async def test_lookup_private_ip_returns_none(mock_reader) -> None:
    """
    Private/loopback IPs return None without hitting the reader.
    """
    service = GeoIPService.__new__(GeoIPService)
    service._reader = mock_reader

    assert await service.lookup("192.168.1.1") is None
    assert await service.lookup("127.0.0.1") is None
    assert await service.lookup("10.0.0.1") is None
    mock_reader.city.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_address_not_found_returns_none(mock_reader) -> None:
    """
    AddressNotFoundError from the reader returns None.
    """
    from geoip2.errors import AddressNotFoundError

    mock_reader.city.side_effect = AddressNotFoundError("8.8.8.8")
    service = GeoIPService.__new__(GeoIPService)
    service._reader = mock_reader

    assert await service.lookup("8.8.8.8") is None


@pytest.mark.asyncio
async def test_lookup_no_reader_returns_none() -> None:
    """
    When no .mmdb file is available, all lookups return None.
    """
    service = GeoIPService.__new__(GeoIPService)
    service._reader = None

    assert await service.lookup("8.8.8.8") is None


@pytest.mark.asyncio
async def test_lookup_missing_city_name(mock_reader) -> None:
    """
    Responses with None city name are handled gracefully.
    """
    mock_reader.city.return_value = _mock_city_response(city_name=None, lat=0.0, lon=0.0)
    service = GeoIPService.__new__(GeoIPService)
    service._reader = mock_reader

    result = await service.lookup("1.1.1.1")
    assert result is not None
    assert result.country == "US"
    assert result.city is None


def test_service_init_missing_db(tmp_path) -> None:
    """
    Initializing with a non-existent .mmdb file sets reader to None.
    """
    service = GeoIPService(db_path=str(tmp_path / "missing.mmdb"))
    assert service._reader is None


def test_service_init_valid_db(tmp_path) -> None:
    """
    Initializing with a valid .mmdb path opens the reader.
    """
    fake_mmdb = tmp_path / "GeoLite2-City.mmdb"
    fake_mmdb.touch()

    with patch("app.core.enrichment.geoip.geoip2.database.Reader") as mock_cls:
        mock_cls.return_value = MagicMock()
        service = GeoIPService(db_path=str(fake_mmdb))
        assert service._reader is not None
        mock_cls.assert_called_once_with(str(fake_mmdb))
