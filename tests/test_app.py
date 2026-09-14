import importlib.util
import io
from pathlib import Path
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location('whichcdn', Path(__file__).parents[1] / 'project_test' / 'whichcdn.py')
appmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(appmod)

@pytest.mark.parametrize('value', ['example.com;whoami', '$(whoami).com', '-x.com', 'http://example.com', 'localhost', '127.0.0.1', 'example.com/path', 'example.com:443', 'example..com'])
def test_rejects_unsafe_domain(value):
    with pytest.raises(ValueError):
        appmod.validate_domain(value)

def test_normalizes_domain():
    assert appmod.validate_domain(' WWW.Example.COM. ') == 'www.example.com'

def test_fingerprint_case_and_specificity():
    assert appmod.find_key(appmod.competitors, 'amazonaws X-AMZ-CF-ID') == 'Amazon CloudFront'
    assert appmod.find_key(appmod.competitors, 'SERVER: CLOUDFLARE') == 'Cloudflare'

def test_private_dns_rejected(monkeypatch):
    class Answer(list):
        response = 'DNS answer'
    resolver = Mock()
    resolver.resolve.return_value = Answer(['127.0.0.1'])
    monkeypatch.setattr(appmod.dns.resolver, 'Resolver', lambda: resolver)
    with pytest.raises(ValueError):
        appmod.resolve_public('example.com')

def test_requests_pin_ip_without_shell(monkeypatch):
    monkeypatch.setattr(appmod, 'resolve_public', lambda d: ('93.184.216.34', 'cloudfront'))
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return Mock(stdout='Server: cloudflare\n__TTFB__:0.123' if args[0] == 'curl' else 'Amazon')
    monkeypatch.setattr(appmod.subprocess, 'run', run)
    result = appmod.analyze('example.com')
    assert result['time'] == '0.123s'
    args, kwargs = calls[0]
    assert '--resolve' in args and 'example.com:443:93.184.216.34' in args
    assert '-L' not in args and '--location' not in args
    assert not kwargs.get('shell', False) and kwargs['timeout'] == 12

def test_routes_and_bad_upload(monkeypatch):
    client = appmod.app.test_client()
    assert client.get('/').status_code == 200
    assert client.get('/csvcdn').status_code == 200
    assert client.post('/csvcdn').status_code == 400
    assert client.post('/', data={'wdname':'x;whoami'}).status_code == 400

def test_csv_bom_header_and_isolation(monkeypatch):
    monkeypatch.setattr(appmod, 'analyze', lambda d: {'domain':d, 'cdn':'Unknown'})
    client = appmod.app.test_client()
    def upload(text):
        return client.post('/csvcdn', data={'csvfile':(io.BytesIO(text.encode('utf-8')), 'domains.csv')})
    first = upload('\ufeffdomain\nexample.com\n')
    second = upload('example.org\n')
    assert first.status_code == second.status_code == 200
    assert b'example.com' in first.data and b'example.com' not in second.data
    assert b'example.org' in second.data
    assert upload('domain\n' + 'example.com\n' * 26).status_code == 400

def test_csv_reports_failures(monkeypatch):
    def fail(d):
        raise ValueError('private address')
    monkeypatch.setattr(appmod, 'analyze', fail)
    response = appmod.app.test_client().post('/csvcdn', data={'csvfile':(io.BytesIO(b'example.com\n'), 'domains.csv')})
    assert response.status_code == 200 and b'Lookup failed' in response.data
