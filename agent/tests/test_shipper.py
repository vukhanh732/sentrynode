import asyncio
import json
import httpx
import pytest
from collector.config import AgentConfig
from collector.shipper import LogShipper

@pytest.fixture
def delays(monkeypatch):
    recorded = []
    async def sleep(seconds):recorded.append(seconds)
    monkeypatch.setattr('collector.shipper.asyncio.sleep', sleep)
    return recorded

def shipper(handler):
    result=LogShipper(AgentConfig(backend_url='http://ingestion.test/'))
    result.http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return result

@pytest.mark.asyncio
async def test_transient_failure_resends_identical_batch(delays):
    payloads=[]
    def handler(request):
        payloads.append(json.loads(request.content))
        return httpx.Response(503 if len(payloads)<3 else 200)
    service=shipper(handler)
    try:assert await service.send_events([{'source':'ssh'}])
    finally:await service.disconnect()
    assert payloads[0]==payloads[1]==payloads[2]
    assert delays==[1,2]

@pytest.mark.asyncio
async def test_429_honors_bounded_retry_after(delays):
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(429,headers={'Retry-After':'999'}) if len(calls)==1 else httpx.Response(200)
    service=shipper(handler)
    try:assert await service.send_events([{}])
    finally:await service.disconnect()
    assert delays==[30]

@pytest.mark.asyncio
async def test_permanent_error_does_not_retry(delays):
    service=shipper(lambda r:httpx.Response(401))
    try:assert not await service.send_events([{}])
    finally:await service.disconnect()
    assert delays==[]

@pytest.mark.asyncio
async def test_transport_exhaustion_and_chunk_size(delays):
    calls=[]
    def failure(request):calls.append(request);raise httpx.ConnectError('offline',request=request)
    service=shipper(failure)
    try:assert not await service.send_events([{}])
    finally:await service.disconnect()
    assert len(calls)==6 and delays==[1,2,4,8,16]
    sizes=[]
    service=shipper(lambda r:(sizes.append(len(json.loads(r.content)['events'])) or httpx.Response(200)))
    try:assert await service.send_events([{}]*1001)
    finally:await service.disconnect()
    assert sizes==[500,500,1]

@pytest.mark.asyncio
async def test_cancellation_propagates(delays):
    def cancel(request):raise asyncio.CancelledError()
    service=shipper(cancel)
    try:
        with pytest.raises(asyncio.CancelledError):await service.send_events([{}])
    finally:await service.disconnect()
