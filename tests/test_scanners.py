import pytest
import asyncio
from vulnexploit.scanners import PortScanner, ServiceScanner, VulnerabilityScanner, OSScanner


class TestPortScanner:
    """Tests for PortScanner module."""
    
    @pytest.fixture
    def scanner(self):
        return PortScanner()
    
    @pytest.mark.asyncio
    async def test_syn_scan(self, scanner):
        """Test SYN scan on localhost."""
        # This test requires a running service on localhost
        result = await scanner.scan('127.0.0.1', [22, 80], 'syn')
        assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_connect_scan(self, scanner):
        """Test TCP connect scan on localhost."""
        result = await scanner.scan('127.0.0.1', [22, 80], 'connect')
        assert isinstance(result, list)
    
    def test_scan_sync(self, scanner):
        """Test synchronous scan method."""
        result = scanner.scan_sync('127.0.0.1', [22, 80])
        assert isinstance(result, list)


class TestServiceScanner:
    """Tests for ServiceScanner module."""
    
    @pytest.fixture
    def scanner(self):
        return ServiceScanner()
    
    @pytest.mark.asyncio
    async def test_banner_grabbing(self, scanner):
        """Test banner grabbing from open ports."""
        open_ports = [{'port': 80, 'service': 'HTTP'}]
        result = await scanner.detect('127.0.0.1', open_ports)
        assert isinstance(result, list)
    
    def test_detect_sync(self, scanner):
        """Test synchronous detect method."""
        open_ports = [{'port': 80, 'service': 'HTTP'}]
        result = scanner.detect_sync('127.0.0.1', open_ports)
        assert isinstance(result, list)


class TestVulnerabilityScanner:
    """Tests for VulnerabilityScanner module."""
    
    @pytest.fixture
    def scanner(self):
        return VulnerabilityScanner()
    
    @pytest.mark.asyncio
    async def test_vulnerability_scan(self, scanner):
        """Test vulnerability scanning."""
        services = [{'port': 80, 'service': 'HTTP', 'version': '2.4.41'}]
        result = await scanner.scan('127.0.0.1', services)
        assert isinstance(result, list)
    
    def test_local_db_lookup(self, scanner):
        """Test local vulnerability database lookup."""
        vulns = scanner._check_local_db('FTP')
        assert isinstance(vulns, list)
        assert len(vulns) > 0
    
    def test_cvss_extraction(self, scanner):
        """Test CVSS score extraction."""
        metrics = {
            'cvssMetricV31': [{
                'cvssData': {'baseScore': 9.8}
            }]
        }
        score = scanner._extract_cvss(metrics)
        assert score == 9.8
    
    @pytest.mark.asyncio
    async def test_close_session(self, scanner):
        """Test closing aiohttp session."""
        await scanner.close()
        assert scanner.session is None


class TestOSScanner:
    """Tests for OSScanner module."""
    
    @pytest.fixture
    def scanner(self):
        return OSScanner()
    
    @pytest.mark.asyncio
    async def test_os_detection(self, scanner):
        """Test OS detection."""
        result = await scanner.detect('127.0.0.1')
        assert isinstance(result, str)
    
    def test_ttl_guessing(self, scanner):
        """Test OS guessing by TTL."""
        assert scanner._guess_os_by_ttl(64) == 'Linux/Unix'
        assert scanner._guess_os_by_ttl(128) == 'Windows'
        assert scanner._guess_os_by_ttl(255) == 'Network Device'
    
    def test_detect_sync(self, scanner):
        """Test synchronous detect method."""
        result = scanner.detect_sync('127.0.0.1')
        assert isinstance(result, str)
