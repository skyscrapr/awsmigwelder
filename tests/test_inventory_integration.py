import pytest
from aws.discovery import Discovery

class DummySession:
    def __init__(self):
        self.profile_name = None
    def set_profile(self, profile):
        self.profile_name = profile

class DummyDiscovery(Discovery):
    def __init__(self):
        self.profile = None
        self.exported = []
    def set_profile(self, profile):
        self.profile = profile
    def export_mgn_server_network_data(self, server_id, output_path):
        self.exported.append((server_id, output_path))
        # Write a dummy CSV file
        with open(output_path, "w") as f:
            f.write("CidrIp,Type,IpProtocol,FromPort,ToPort\n10.0.0.0/24,ingress,tcp,80,80\n")
        return True

def test_inventory_process(tmp_path):
    from migwelder.inventory import Inventory
    inv_file = tmp_path / "inv.csv"
    with open(inv_file, "w") as f:
        f.write("MGNServerID,AWSProfile,SourceIPAddress,TargetIPAddress\nserver1,profile1,10.0.0.1,10.0.0.2\n")
    d = DummyDiscovery()
    inv = Inventory(d)
    inv.load_inventory(inv_file)
    out_dir = tmp_path / "out"
    exclusions = []
    networks = None
    firewalls = tmp_path / "fw.csv"
    with open(firewalls, "w") as f:
        f.write("Name,Source,Destination,FromPort,ToPort,Protocol\nfw1,10.0.0.0/16,10.0.0.0/16,80,80,TCP\n")
    defaults = tmp_path / "defaults.csv"
    with open(defaults, "w") as f:
        f.write("AccountId,Hostname,Type,IpProtocol,FromPort,ToPort,CidrIp,Description,FWRule\n,,ingress,tcp,80,80,10.0.0.0/24,desc,\n")
    inv.process(out_dir, exclusions, networks, firewalls, defaults)
    # Check output files exist
    assert (out_dir / "1-Raw/server1.csv").exists()
    assert (out_dir / "2-Source/server1.csv").exists()
    assert (out_dir / "3-Target/server1.csv").exists()
    assert (out_dir / "4-Consolidated/server1.csv").exists()
    # Check combined output
    assert (out_dir / "1-Raw.csv").exists()
    assert (out_dir / "2-Source.csv").exists()
    assert (out_dir / "3-Target.csv").exists()
    assert (out_dir / "4-Consolidated.csv").exists()
