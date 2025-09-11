import pytest
from aws.discovery import Discovery

# def test_set_profile():
#     d = Discovery()
#     d.set_profile("test-profile")
#     assert hasattr(d, "_profile") or hasattr(d, "profile")

# def test_export_mgn_server_network_data(monkeypatch, tmp_path):
#     d = Discovery()
#     # Patch boto3 client and file writing
#     class DummyClient:
#         def describe_source_servers(self, **kwargs):
#             return {"Items": [{"sourceServerID": "srv-1"}]}
#         def describe_network_interfaces(self, **kwargs):
#             return {"NetworkInterfaces": []}
#     monkeypatch.setattr("boto3.Session", lambda *a, **kw: type("S", (), {"client": lambda self, n: DummyClient()})())
#     output_file = tmp_path / "out.csv"
#     # Should not raise
#     try:
#         d.export_mgn_server_network_data("srv-1", str(output_file))
#     except Exception as e:
#         pytest.fail(f"export_mgn_server_network_data raised: {e}")
